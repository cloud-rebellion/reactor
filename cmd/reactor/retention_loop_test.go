package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestRunRetentionLoopSweepsOnStartupAndMinuteTick(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	url := "sqlite://" + filepath.Join(t.TempDir(), "retention.db")
	if err := migrate.Up(ctx, log, url); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EngineSQLite {
		t.Fatalf("retention test database engine = %s", engine)
	}
	j := journal.New(db, journal.EngineSQLite)
	if err := j.CreateWorkflow(ctx, "wf_retention_loop", "retention-loop", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	makeOldRun := func(id string) {
		t.Helper()
		if err := j.CreateRun(ctx, id, "wf_retention_loop", "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := j.MarkRunFinished(ctx, id, "succeeded"); err != nil {
			t.Fatal(err)
		}
		old := time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z")
		if _, err := db.ExecContext(ctx, `UPDATE runs SET created_at = ?, finished_at = ? WHERE id = ?`, old, old, id); err != nil {
			t.Fatal(err)
		}
	}
	waitDeleted := func(id string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_, err := j.GetRun(ctx, id)
			if errors.Is(err, journal.ErrNotFound) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("retention loop did not purge %s", id)
	}
	makeOldRun("retention_startup")
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	historyTick := make(chan time.Time, 1)
	deps := &serveDeps{journal: j, authStore: auth.New(db, auth.EngineSQLite)}
	go func() {
		defer close(done)
		runRetentionLoopOnTicks(loopCtx, log, deps, 30*24*time.Hour, 7, nil, historyTick)
	}()
	defer func() {
		cancel()
		<-done
	}()
	waitDeleted("retention_startup")

	// A run that becomes eligible after startup is not left for the hourly
	// ephemeral sweep; the independent history tick advances it.
	makeOldRun("retention_tick")
	historyTick <- time.Now()
	waitDeleted("retention_tick")
}
