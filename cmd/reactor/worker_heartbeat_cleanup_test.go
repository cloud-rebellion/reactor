package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

type blockedWorkerRegistry struct {
	entered chan struct{}
	release chan struct{}
	deleted chan struct{}
}

func (r *blockedWorkerRegistry) UpsertWorkerHeartbeat(context.Context, string, int) error {
	close(r.entered)
	<-r.release
	return nil
}

func (r *blockedWorkerRegistry) DeleteWorker(context.Context, string) error {
	close(r.deleted)
	return nil
}

func TestWorkerHeartbeatCannotRecreateRegistryRowAfterUnregister(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	registry := &blockedWorkerRegistry{
		entered: make(chan struct{}), release: make(chan struct{}), deleted: make(chan struct{}),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		heartbeatWorker(ctx, log, registry, "worker-a", 2, time.Millisecond, cancel)
	}()
	select {
	case <-registry.entered:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not enter the database write")
	}
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		stopWorkerHeartbeatAndUnregister(cancel, heartbeatDone, registry, "worker-a", log)
	}()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("worker cleanup did not cancel the heartbeat")
	}
	select {
	case <-registry.deleted:
		t.Fatal("worker row was deleted while an upsert could still recreate it")
	default:
	}
	close(registry.release)
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("worker cleanup did not finish after the heartbeat returned")
	}
	select {
	case <-registry.deleted:
	default:
		t.Fatal("worker row was not deleted after the heartbeat stopped")
	}
}
