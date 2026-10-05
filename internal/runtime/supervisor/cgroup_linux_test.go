//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKillCgroupProcessesWritesKernelKillRequest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup.kill")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := killCgroupProcesses(dir); err != nil {
		t.Fatalf("killCgroupProcesses: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "1" {
		t.Fatalf("cgroup.kill = %q, want 1", b)
	}
}

func TestKillCgroupProcessesReportsMissingKernelInterface(t *testing.T) {
	err := killCgroupProcesses(t.TempDir())
	if !os.IsNotExist(err) {
		t.Fatalf("killCgroupProcesses error = %v, want missing cgroup.kill", err)
	}
}
