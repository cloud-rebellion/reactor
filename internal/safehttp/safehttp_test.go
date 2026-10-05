package safehttp

import (
	"context"
	"net"
	"strings"
	"testing"
)

// TestBlockedIP covers the outbound egress boundary. This package had no test
// file at all before the 2026-07-25 audit, despite being the only thing between
// a tenant-supplied webhook or rotation-delivery URL and the internal network.
func TestBlockedIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		ip           string
		allowPrivate bool
		want         bool
	}{
		// The range that actually bit this estate: 100.64.0.0/10 is the
		// Tailscale tailnet, and net.IP.IsPrivate does NOT classify it as
		// private, so it used to pass even with allowPrivate=false (the
		// enforcing configuration used for notification webhooks).
		{"CGNAT tailnet blocked", "100.101.102.103", false, true},
		{"CGNAT tailnet blocked even when private is allowed", "100.64.0.1", true, true},

		// Always blocked, regardless of allowPrivate: the cloud metadata
		// endpoint is the classic SSRF credential-theft prize.
		{"cloud metadata blocked", "169.254.169.254", false, true},
		{"cloud metadata blocked under allowPrivate", "169.254.169.254", true, true},
		{"unspecified blocked", "0.0.0.0", true, true},
		{"multicast blocked", "224.0.0.1", true, true},

		{"loopback blocked by default", "127.0.0.1", false, true},
		{"loopback allowed under allowPrivate", "127.0.0.1", true, false},
		{"rfc1918 blocked by default", "10.1.2.3", false, true},
		{"rfc1918 allowed under allowPrivate", "192.168.1.5", true, false},

		// IPv4-mapped IPv6 must fold to its v4 form, or ::ffff:127.0.0.1
		// would sail past both IsLoopback and IsPrivate.
		{"ipv4-mapped loopback blocked", "::ffff:127.0.0.1", false, true},
		{"ipv6 ULA blocked by default", "fc00::1", false, true},
		{"NAT64 blocked", "64:ff9b::7f00:1", false, true},

		{"reserved 240/4 blocked", "240.0.0.1", false, true},
		{"TEST-NET-1 blocked", "192.0.2.5", false, true},

		{"public address allowed", "93.184.216.34", false, false},
		{"public ipv6 allowed", "2606:2800:220:1:248:1893:25c8:1946", false, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test fixture: %q does not parse", tc.ip)
			}
			if got := BlockedIP(ip, tc.allowPrivate); got != tc.want {
				t.Fatalf("BlockedIP(%s, allowPrivate=%v) = %v, want %v", tc.ip, tc.allowPrivate, got, tc.want)
			}
		})
	}
}

func TestDialContextAppliesSSRFPolicyToNonHTTPProtocols(t *testing.T) {
	_, err := DialContext(context.Background(), "tcp", "127.0.0.1:1", false)
	if err == nil || !strings.Contains(err.Error(), "ssrf: refusing") {
		t.Fatalf("DialContext error=%v, want SSRF refusal", err)
	}
}

// TestExtraBlockedNetsParsed guards against a typo silently disabling a range:
// the CIDR list is parsed at init and a bad entry is skipped, so a malformed
// string would remove protection with no error anywhere.
func TestExtraBlockedNetsParsed(t *testing.T) {
	t.Parallel()
	if len(extraBlockedNets) != 10 {
		t.Fatalf("extraBlockedNets has %d entries, want 10; a malformed CIDR is skipped silently", len(extraBlockedNets))
	}
}
