package autoscale

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessSpawnerSpawnStopReap(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary on PATH")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sp := NewProcessSpawner(sleep, []string{"30"}, nil, log)
	defer sp.StopAll(context.Background())

	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	newest, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sp.Running() != 2 {
		t.Fatalf("after spawn: running=%d, want 2", sp.Running())
	}
	if ids := sp.IDs(); len(ids) != 2 || ids[0] != id || ids[1] != newest {
		t.Fatalf("IDs=%v, want spawn order [%s %s]", ids, id, newest)
	}
	if err := sp.Stop(context.Background(), newest); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for sp.Running() != 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ids := sp.IDs(); len(ids) != 1 || ids[0] != id {
		t.Fatalf("IDs after reaping newest=%v, want [%s]", ids, id)
	}
	if err := sp.Stop(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	// Stop is async (SIGTERM); the reap goroutine removes the entry when the
	// process exits. Poll briefly.
	deadline = time.Now().Add(3 * time.Second)
	for sp.Running() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if sp.Running() != 0 {
		t.Fatalf("worker not reaped after Stop, running=%d", sp.Running())
	}
}

func TestProcessSpawnerDoesNotLaunchAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sp := NewProcessSpawner("ignored", nil, nil, nil)
	if _, err := sp.Spawn(ctx); err != context.Canceled {
		t.Fatalf("Spawn with cancelled leader = %v, want context cancellation", err)
	}
	if sp.Running() != 0 {
		t.Fatal("cancelled leader launched a worker")
	}
}

func TestProcessSpawnerParentGuardHelper(t *testing.T) {
	if os.Getenv("REACTOR_AUTOSCALE_GUARD_HELPER") != "1" {
		return
	}
	if os.Getenv("REACTOR_WORKER_PARENT_FD") != "3" {
		t.Fatal("parent liveness descriptor was not advertised")
	}
	pipe := os.NewFile(3, "parent-liveness")
	if pipe == nil {
		t.Fatal("parent liveness descriptor is unavailable")
	}
	defer pipe.Close()
	info, err := pipe.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("parent liveness descriptor is not a pipe: %v", err)
	}
	if _, err := io.Copy(io.Discard, pipe); err != nil {
		t.Fatalf("read parent pipe: %v", err)
	}
	if err := os.WriteFile(os.Getenv("REACTOR_AUTOSCALE_GUARD_MARKER"), []byte("eof"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSpawnerParentGuardSurvivesUntilParentClosesIt(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "parent-eof")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	env := append(os.Environ(), "REACTOR_AUTOSCALE_GUARD_HELPER=1", "REACTOR_AUTOSCALE_GUARD_MARKER="+marker)
	sp := NewProcessSpawner(os.Args[0], []string{"-test.run=^TestProcessSpawnerParentGuardHelper$"}, env, log)
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sp.StopAll(context.Background())
	sp.mu.Lock()
	guard := sp.guards[id]
	sp.mu.Unlock()
	if guard == nil {
		t.Fatal("spawner lost the parent liveness writer")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for sp.Running() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sp.Running() != 0 {
		sp.StopAll(context.Background())
		t.Fatal("child did not exit after parent liveness pipe closed")
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "eof" {
		t.Fatalf("child did not observe parent EOF: marker=%q err=%v", raw, err)
	}
}
