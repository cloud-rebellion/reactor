package main

import "testing"

func TestValidateMCPExposureAllowsExplicitLoopbackNoAuth(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:7777", "[::1]:7777", "localhost:7777", "[::1%lo0]:7777"} {
		t.Run(addr, func(t *testing.T) {
			if err := validateMCPExposure(addr, "", true, false, false, false); err != nil {
				t.Fatalf("loopback no-auth address rejected: %v", err)
			}
		})
	}
}

func TestValidateMCPExposureRejectsUnauthenticatedNonLoopback(t *testing.T) {
	for _, addr := range []string{":7777", "0.0.0.0:7777", "[::]:7777", "192.0.2.10:7777"} {
		t.Run(addr, func(t *testing.T) {
			if err := validateMCPExposure(addr, "", true, false, false, false); err == nil {
				t.Fatal("non-loopback no-auth address was accepted")
			}
		})
	}
}

func TestValidateMCPExposurePreservesConfiguredAuth(t *testing.T) {
	for _, tc := range []struct {
		name         string
		addr         string
		mcpToken     string
		noAuth       bool
		dashAuth     bool
		trustedProxy bool
	}{
		{name: "dashboard credentials", addr: ":7777", noAuth: true, dashAuth: true, trustedProxy: true},
		{name: "dedicated bearer", addr: ":7777", mcpToken: "mcp-secret", noAuth: true, trustedProxy: true},
		{name: "auth required mode", addr: ":7777", noAuth: false, trustedProxy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateMCPExposure(tc.addr, tc.mcpToken, tc.noAuth, tc.dashAuth, false, tc.trustedProxy); err != nil {
				t.Fatalf("configured auth rejected: %v", err)
			}
		})
	}
}

func TestValidateMCPExposureRequiresConfidentialRemoteTransport(t *testing.T) {
	if err := validateMCPExposure("192.0.2.10:7777", "mcp-secret", false, true, false, false); err == nil {
		t.Fatal("authenticated remote plain HTTP MCP was accepted")
	}
	if err := validateMCPExposure("192.0.2.10:7777", "mcp-secret", false, true, true, false); err != nil {
		t.Fatalf("TLS-protected remote MCP rejected: %v", err)
	}
	if err := validateMCPExposure("192.0.2.10:7777", "mcp-secret", false, true, false, true); err != nil {
		t.Fatalf("explicit trusted-proxy MCP rejected: %v", err)
	}
}

func TestIsLoopbackListenAddrDoesNotTrustHostnames(t *testing.T) {
	for _, addr := range []string{"reactor.internal:7777", "example.test:7777", "7777"} {
		if isLoopbackListenAddr(addr) {
			t.Fatalf("non-literal address %q treated as loopback", addr)
		}
	}
}

func TestParseServeFlagsRejectsWildcardNoAuthWithoutMCPBearer(t *testing.T) {
	for _, name := range []string{
		"REACTOR_MCP_TOKEN", "ARACHNE_MCP_TOKEN",
		"REACTOR_BASIC_AUTH_USER", "ARACHNE_BASIC_AUTH_USER",
		"REACTOR_BASIC_AUTH_PASSWORD_SHA256", "ARACHNE_BASIC_AUTH_PASSWORD_SHA256",
	} {
		t.Setenv(name, "")
	}
	key := reactorTestMasterKey
	_, err := parseServeFlags([]string{
		"--db", "sqlite://reactor.db",
		"--root", t.TempDir(),
		"--master-key", key,
		"--addr", ":7777",
		"--insecure-no-auth",
	})
	if err == nil {
		t.Fatal("wildcard no-auth serve configuration was accepted without MCP bearer")
	}
}
