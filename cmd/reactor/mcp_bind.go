package main

import (
	"fmt"
	"net"
	"strings"
)

// validateMCPExposure keeps the explicit no-auth development mode local. The
// Mesh HTTP transport applies the same boundary: a loopback listener may be
// tokenless, while a listener reachable from another host must have TLS. A
// plain HTTP listener on a non-loopback address is accepted only with the
// explicit trusted-proxy assertion, meaning an operator has placed an
// authenticated TLS-terminating proxy in front of this process. Credentials
// alone are not a substitute for transport confidentiality.
func validateMCPExposure(addr, mcpToken string, insecureNoAuth, dashboardAuthConfigured, tlsConfigured, trustedProxy bool) error {
	if !isLoopbackListenAddr(addr) && !tlsConfigured && !trustedProxy {
		return fmt.Errorf("refusing plain HTTP MCP on non-loopback address %q: configure TLS or explicitly assert --mcp-trusted-proxy for an authenticated TLS-terminating proxy", addr)
	}
	if !insecureNoAuth || dashboardAuthConfigured || strings.TrimSpace(mcpToken) != "" {
		return nil
	}
	if isLoopbackListenAddr(addr) {
		return nil
	}
	return fmt.Errorf("refusing unauthenticated MCP on non-loopback address %q: set --mcp-token (or REACTOR_MCP_TOKEN), configure dashboard credentials, or bind to loopback", addr)
}

// isLoopbackListenAddr deliberately treats an empty host (":7777") and
// wildcard addresses as non-loopback. net/http interprets those as all
// interfaces, which is exactly the exposure the no-auth guard must reject.
// Hostname resolution is intentionally not performed: accepting an arbitrary
// name based on a mutable DNS answer would make the startup decision unstable.
func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// ParseIP does not accept a zone suffix; strip it only after SplitHostPort
	// has identified the host so an IPv6 loopback listener such as [::1%lo0]
	// remains local.
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
