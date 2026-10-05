package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/cron"
)

func TestRunLeaderTasksFailsWhenCronCannotStart(t *testing.T) {
	_, j := newSeededDB(t)
	if _, err := j.CreateCronTrigger(context.Background(), "wf_t", json.RawMessage(`{"spec":"not a cron expression"}`)); err != nil {
		t.Fatalf("seed malformed cron trigger: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := runLeaderTasks(context.Background(), log, &serveConfig{mode: "local"}, &serveDeps{
		cronDriver: &cron.Driver{Journal: j, Log: log},
	})
	if err == nil || !strings.Contains(err.Error(), "start cron driver") {
		t.Fatalf("leader startup error = %v, want cron startup failure", err)
	}
}

func TestRunLeaderComponentReportsUnexpectedExit(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	want := errors.New("journal unavailable")
	if err := runLeaderComponent(context.Background(), log, "scheduler", func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("scheduler error = %v, want wrapped %v", err, want)
	}
	if err := runLeaderComponent(context.Background(), log, "rotation_runner", func() error { return nil }); err == nil || !strings.Contains(err.Error(), "exited before shutdown") {
		t.Fatalf("clean early exit = %v, want failure", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runLeaderComponent(cancelled, log, "scheduler", func() error { return context.Canceled }); err != nil {
		t.Fatalf("normal shutdown = %v, want nil", err)
	}
}
