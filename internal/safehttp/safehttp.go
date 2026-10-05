// Package safehttp provides an *http.Client hardened against SSRF, shared by
// every daemon subsystem that dials an operator- or workflow-influenced URL
// (webhook notifiers, credential-rotation delivery). Centralising it means the
// guard cannot be applied to one HTTP client and forgotten on another.
package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// Client returns an *http.Client hardened against SSRF. Two layers:
//
//   - A Dialer.Control hook inspects the ACTUAL resolved IP right before
//     connect and refuses blocked addresses. Checking at connect time (not
//     before) also defeats DNS rebinding, where a name resolves to a public IP
//     on the first lookup and a private/metadata one on the connect lookup.
//   - CheckRedirect refuses to follow redirects, so a 302 to
//     http://169.254.169.254/ can't smuggle a request (or a rotated secret)
//     past the URL check.
//
// allowPrivate lets a self-hosted daemon reach loopback/RFC1918 internal
// services (credential rotation legitimately targets internal reload
// endpoints). Link-local (incl. the 169.254.169.254 cloud-metadata endpoint),
// unspecified, multicast, reserved/test ranges, NAT64, and the Tailscale
// 100.64.0.0/10 tailnet are ALWAYS blocked regardless.
func Client(allowPrivate bool) *http.Client {
	d := dialer(allowPrivate)
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("ssrf: redirects are not followed")
		},
	}
}

// DialContext applies the same connect-time IP policy as Client to protocols
// that do not use net/http, such as SMTP notification delivery.
func DialContext(ctx context.Context, network, address string, allowPrivate bool) (net.Conn, error) {
	return dialer(allowPrivate).DialContext(ctx, network, address)
}

func dialer(allowPrivate bool) *net.Dialer {
	return &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("ssrf: bad address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("ssrf: unresolved address %q", host)
			}
			if BlockedIP(ip, allowPrivate) {
				return fmt.Errorf("ssrf: refusing to connect to non-public address %s", ip)
			}
			return nil
		},
	}
}

// BlockedIP reports whether an IP is in a range an outbound request must never
// reach. Link-local (which includes the 169.254.169.254 cloud-metadata
// endpoint), unspecified, and multicast are ALWAYS blocked: those are never a
// legitimate target and the metadata endpoint is the classic SSRF
// credential-theft prize. Loopback + private (RFC1918 + IPv6 ULA) are blocked
// by default but allowed when allowPrivate is set.
func BlockedIP(ip net.IP, allowPrivate bool) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// These ranges are never valid external service targets, even when a
	// caller explicitly opts into RFC1918 access for a self-hosted endpoint.
	// In particular, 100.64.0.0/10 is the Tailscale/CGNAT tailnet: treating
	// allowPrivate as a blanket bypass would let an operator-configured OAuth,
	// webhook, or rotation URL reach any service on the host's tailnet. NAT64
	// and the reserved/test ranges are likewise not legitimate destinations.
	for _, cidr := range extraBlockedNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	if allowPrivate {
		return false
	}
	// net.IP.IsPrivate covers RFC1918 + IPv6 ULA. Those remain available to an
	// explicitly self-hosted caller via allowPrivate, while the ranges above
	// are always denied.
	return ip.IsLoopback() || ip.IsPrivate()
}

// extraBlockedNets are ranges net.IP.IsPrivate does not classify as private
// but which must never be an outbound target.
var extraBlockedNets = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",   // RFC6598 CGNAT (Tailscale tailnet)
		"0.0.0.0/8",       // "this host on this network"
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved
		"64:ff9b::/96",    // NAT64, maps arbitrary IPv4 incl. loopback
		"::/128",          // unspecified (belt and braces)
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()
