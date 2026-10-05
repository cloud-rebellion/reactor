package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPackagedSystemdUnitUsesInstalledBinary guards the operator path shared
// by nfpm packages and the checked-in systemd unit. A package can install
// cleanly while systemd still fails immediately if these paths drift.
func TestPackagedSystemdUnitUsesInstalledBinary(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	unit, err := os.ReadFile(filepath.Join(root, "deploy", "reactor.service"))
	if err != nil {
		t.Fatalf("read systemd unit: %v", err)
	}
	nfpm, err := os.ReadFile(filepath.Join(root, "packaging", "nfpm.yaml"))
	if err != nil {
		t.Fatalf("read nfpm manifest: %v", err)
	}

	const installedPath = "/usr/bin/reactor"
	if !strings.Contains(string(nfpm), "dst: "+installedPath) {
		t.Fatalf("nfpm manifest no longer installs %s", installedPath)
	}
	if !strings.Contains(string(unit), installedPath+" serve --root /var/lib/reactor") {
		t.Fatalf("systemd unit does not execute the packaged binary at %s", installedPath)
	}
	if !strings.Contains(string(unit), "REACTOR_SDK_REPLACE=/usr/lib/reactor-sdk") {
		t.Fatal("systemd unit does not pin its packaged workflow SDK")
	}
	if !strings.Contains(string(unit), installedPath+" serve --root /var/lib/reactor --addr 127.0.0.1:7777") {
		t.Fatalf("systemd unit must bind the unauthenticated local example to loopback")
	}
	legacyEnv := strings.Index(string(unit), "EnvironmentFile=-/etc/reactor/reactor.env")
	newEnv := strings.Index(string(unit), "EnvironmentFile=-/var/lib/reactor/reactor.env")
	if legacyEnv < 0 || newEnv < legacyEnv {
		t.Fatal("systemd unit must preserve legacy auth/DB settings and let setup-generated settings win")
	}
	for _, want := range []string{
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateTmp=true",
		"PrivateDevices=true",
		"RestrictNamespaces=true",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("systemd unit lost hardening directive %q", want)
		}
	}
}

// TestServeDefaultsToLoopback keeps the ordinary `reactor serve` quickstart
// compatible with the MCP exposure fence. Remote binds must remain an explicit
// operator choice so a default startup can never expose plain HTTP MCP on all
// interfaces.
func TestServeDefaultsToLoopback(t *testing.T) {
	key := reactorTestMasterKey
	cfg, err := parseServeFlags([]string{
		"--db", "sqlite://reactor.db",
		"--root", t.TempDir(),
		"--master-key", key,
	})
	if err != nil {
		t.Fatalf("parse default serve flags: %v", err)
	}
	if got, want := cfg.addr, "127.0.0.1:7777"; got != want {
		t.Fatalf("default serve address = %q, want %q", got, want)
	}
}

// TestComposeExampleKeepsAnOuterWorkflowFence makes the local deployment
// example honest about the boundary it provides. The supervisor's per-run
// cgroup mode needs host delegation, which Compose cannot assume; the
// container still needs a whole-process memory/pid fence and dropped caps.
func TestComposeExampleKeepsAnOuterWorkflowFence(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	compose, err := os.ReadFile(filepath.Join(root, "deploy", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read compose example: %v", err)
	}
	text := string(compose)
	for _, want := range []string{
		"init: true",
		"read_only: true",
		"/tmp:rw,noexec,nosuid,nodev",
		"cap_drop:",
		"- ALL",
		"no-new-privileges:true",
		"mem_limit:",
		"pids_limit:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("compose example missing outer workflow fence %q", want)
		}
	}
	if !strings.Contains(text, "network_mode: host") || !strings.Contains(text, "--addr=127.0.0.1:7777") {
		t.Fatal("compose local example must use host networking with an explicit loopback bind")
	}
	if !strings.Contains(text, "readyz") {
		t.Fatal("compose local example must probe /readyz before receiving work")
	}
}
