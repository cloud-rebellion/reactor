package autoscale

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestCommandSpawnerUsesStdoutAsID(t *testing.T) {
	sp := NewCommandSpawner([]string{"printf", "container-abc123"}, []string{"true", "{id}"}, nil, quietLog())
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "container-abc123" {
		t.Fatalf("id = %q, want container-abc123", id)
	}
	if sp.Running() != 1 {
		t.Fatalf("running = %d, want 1", sp.Running())
	}
	if got := sp.IDs(); len(got) != 1 || got[0] != "container-abc123" {
		t.Fatalf("ids = %v", got)
	}
}

func TestCommandSpawnerSynthesizesIDWhenNoStdout(t *testing.T) {
	sp := NewCommandSpawner([]string{"true"}, []string{"true", "{id}"}, nil, quietLog())
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "cmd-1" {
		t.Fatalf("synthesized id = %q, want cmd-1", id)
	}
	if err := sp.Stop(context.Background(), id); err == nil || sp.Running() != 1 {
		t.Fatalf("unaddressable stop = %v, tracked = %d; want error and retained capacity slot", err, sp.Running())
	}
}

func TestCommandSpawnerReservesCapacityAfterAmbiguousLaunchFailure(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "launches")
	sp := NewCommandSpawner(
		[]string{"sh", "-c", `printf x >> "$1"; exit 17`, "sh", marker},
		[]string{"true", "{id}"}, nil, quietLog())
	ctrl := New(Config{Max: 1, QueuePerWorker: 1, ScaleUpCooldown: time.Second},
		sp, &fakeDemand{queued: 10}, quietLog())
	ctrl.tick(context.Background())
	if got := sp.IDs(); len(got) != 1 || got[0] != "cmd-1" {
		t.Fatalf("failed post-start launch must hold one unaddressable slot, got %v", got)
	}
	if err := sp.Stop(context.Background(), "cmd-1"); err == nil || sp.Running() != 1 {
		t.Fatalf("unknown launch must not be silently released: stop=%v running=%d", err, sp.Running())
	}
	ctrl.tick(context.Background())
	launches, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(launches) != "x" {
		t.Fatalf("controller retried after an uncertain launch despite Max=1: %q", launches)
	}
}

func TestCommandSpawnerDoesNotReserveWhenLauncherCouldNotStart(t *testing.T) {
	sp := NewCommandSpawner([]string{filepath.Join(t.TempDir(), "missing-launcher")},
		[]string{"true", "{id}"}, nil, quietLog())
	if _, err := sp.Spawn(context.Background()); err == nil {
		t.Fatal("missing launcher unexpectedly started")
	}
	if got := sp.Running(); got != 0 {
		t.Fatalf("failed process start reserved %d slots; want a retryable zero", got)
	}
}

func TestCommandSpawnerKeepsUnsafeLauncherIDUnaddressable(t *testing.T) {
	for _, launcherID := range []string{"worker-1;echo unsafe", "a/../../target", "job.batch/../target"} {
		t.Run(launcherID, func(t *testing.T) {
			sp := NewCommandSpawner([]string{"printf", launcherID}, []string{"true", "{id}"}, nil, quietLog())
			id, err := sp.Spawn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if id != "cmd-1" {
				t.Fatalf("unsafe launcher output returned as stop target: %q", id)
			}
			if err := sp.Stop(context.Background(), id); err == nil || sp.Running() != 1 {
				t.Fatalf("unsafe id stop = %v, tracked = %d; want error and retained handle", err, sp.Running())
			}
		})
	}
}

func TestCommandSpawnerAcceptsKubernetesJobID(t *testing.T) {
	sp := NewCommandSpawner([]string{"printf", "job.batch/reactor-worker-abc123"}, []string{"true", "{id}"}, nil, quietLog())
	id, err := sp.Spawn(context.Background())
	if err != nil || id != "job.batch/reactor-worker-abc123" {
		t.Fatalf("Kubernetes Job ID = %q, %v", id, err)
	}
	if err := sp.Stop(context.Background(), id); err != nil || sp.Running() != 0 {
		t.Fatalf("Kubernetes Job stop = %v, tracked = %d", err, sp.Running())
	}
}

func TestCommandSpawnerStopUntracksOnSuccess(t *testing.T) {
	sp := NewCommandSpawner([]string{"printf", "abc"}, []string{"true", "{id}"}, nil, quietLog())
	id, _ := sp.Spawn(context.Background())
	if err := sp.Stop(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if sp.Running() != 0 {
		t.Fatalf("running after stop = %d, want 0", sp.Running())
	}
}

func TestCommandSpawnerStopKeepsTrackedOnFailure(t *testing.T) {
	// `false` exits non-zero: the worker stays tracked so the next tick retries
	// rather than silently leaking the container.
	sp := NewCommandSpawner([]string{"printf", "abc"}, []string{"false", "{id}"}, nil, quietLog())
	id, _ := sp.Spawn(context.Background())
	if err := sp.Stop(context.Background(), id); err == nil {
		t.Fatal("expected stop to return the command error")
	}
	if sp.Running() != 1 {
		t.Fatalf("running after failed stop = %d, want 1 (kept for retry)", sp.Running())
	}
}

func TestCommandSpawnerStopUntracksAlreadyGoneWorker(t *testing.T) {
	// Exercise the built-in Docker removal shape without requiring a daemon.
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\necho 'Error response from daemon: No such container: abc' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sp := NewCommandSpawner([]string{"printf", "abc"}, []string{docker, "rm", "-f", "{id}"}, nil, quietLog())
	id, _ := sp.Spawn(context.Background())
	if err := sp.Stop(context.Background(), id); err != nil {
		t.Fatalf("already-gone stop should be successful: %v", err)
	}
	if sp.Running() != 0 {
		t.Fatalf("running after already-gone stop = %d, want 0", sp.Running())
	}
}

func TestCommandSpawnerGracefulDockerStopUntracksExactMissingWorker(t *testing.T) {
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\necho 'Error response from daemon: No such container: abc' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sp := NewCommandSpawner([]string{"printf", "abc"}, []string{docker, "stop", "--signal", "SIGTERM", "--time", "35", "{id}"}, nil, quietLog())
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Stop(context.Background(), id); err != nil || sp.Running() != 0 {
		t.Fatalf("exact missing Docker stop = %v; tracked = %d, want zero", err, sp.Running())
	}
}

func TestCommandSpawnerStopDoesNotUntrackDifferentMissingContainer(t *testing.T) {
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\necho 'Error response from daemon: No such container: different' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sp := NewCommandSpawner([]string{"printf", "abc"}, []string{docker, "rm", "-f", "{id}"}, nil, quietLog())
	id, _ := sp.Spawn(context.Background())
	if err := sp.Stop(context.Background(), id); err == nil || sp.Running() != 1 {
		t.Fatalf("unrelated missing container = %v; tracked = %d, want failure and retained slot", err, sp.Running())
	}
}

func TestCommandSpawnerDoesNotLogCLIErrorBodies(t *testing.T) {
	const sensitive = "credential-from-provider"
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	spawn := NewCommandSpawner(
		[]string{"sh", "-c", "printf '%s\\n' 'credential-from-provider' >&2; exit 1"},
		[]string{"true", "{id}"}, nil, logger)
	if _, err := spawn.Spawn(context.Background()); err == nil || strings.Contains(err.Error(), sensitive) {
		t.Fatalf("spawn failure exposed CLI stderr: %v", err)
	}

	stop := NewCommandSpawner([]string{"printf", "abc"},
		[]string{"sh", "-c", "printf '%s\\n' 'credential-from-provider' >&2; exit 1", "{id}"}, nil, logger)
	id, err := stop.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stop.Stop(context.Background(), id); err == nil || stop.Running() != 1 {
		t.Fatalf("stop failure = %v; tracked = %d", err, stop.Running())
	}
	if strings.Contains(logs.String(), sensitive) {
		t.Fatalf("CLI stderr appeared in autoscaler log: %s", logs.String())
	}
}

func TestCommandSpawnerSubstitutesID(t *testing.T) {
	got := substituteID([]string{"docker", "stop", "{id}"}, "deadbeef")
	if len(got) != 3 || got[2] != "deadbeef" {
		t.Fatalf("substituteID = %v", got)
	}
	// The original argv must not be mutated (it is reused for every Stop).
	orig := []string{"kubectl", "delete", "{id}"}
	_ = substituteID(orig, "pod/x")
	if orig[2] != "{id}" {
		t.Fatalf("substituteID mutated the input: %v", orig)
	}
}

func TestCommandSpawnerEmptySpawnArgvErrors(t *testing.T) {
	sp := NewCommandSpawner(nil, nil, nil, quietLog())
	if _, err := sp.Spawn(context.Background()); err == nil {
		t.Fatal("expected an error for an empty spawn command")
	}
}

func TestCommandSpawnerRefusesUnmanageableWorkers(t *testing.T) {
	for _, stop := range [][]string{nil, {"true"}} {
		sp := NewCommandSpawner([]string{"printf", "abc"}, stop, nil, quietLog())
		if _, err := sp.Spawn(context.Background()); err == nil {
			t.Fatalf("spawn with stop command %v succeeded without a targeted stop", stop)
		}
		if got := sp.Running(); got != 0 {
			t.Fatalf("spawn with stop command %v tracked %d workers", stop, got)
		}
	}
	sp := NewCommandSpawner([]string{"printf", "abc"}, []string{"true", "{id}"}, nil, quietLog())
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sp.StopArgv = nil // Guard remains fail-closed if configuration changes after Spawn.
	if err := sp.Stop(context.Background(), id); err == nil || sp.Running() != 1 {
		t.Fatalf("stop without command = %v, tracked = %d; want error and retained handle", err, sp.Running())
	}
}

func TestCommandSpawnerAmbiguousStopFailureKeepsWorkerTracked(t *testing.T) {
	sp := NewCommandSpawner([]string{"printf", "abc"}, []string{"sh", "-c", "echo 'namespace not found' >&2; exit 1", "{id}"}, nil, quietLog())
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Stop(context.Background(), id); err == nil || sp.Running() != 1 {
		t.Fatalf("ambiguous stop failure = %v, tracked = %d; want error and retained handle", err, sp.Running())
	}
}

func TestCommandSpawnerStopAllDrains(t *testing.T) {
	sp := NewCommandSpawner([]string{"printf", "x"}, []string{"true", "{id}"}, nil, quietLog())
	// printf "x" yields the same id each time; track three distinct via seq is
	// not the goal here -- just verify StopAll empties the set.
	_, _ = sp.Spawn(context.Background())
	sp.StopAll(context.Background())
	if sp.Running() != 0 {
		t.Fatalf("running after StopAll = %d, want 0", sp.Running())
	}
}
