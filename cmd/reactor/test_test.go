package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestCmdTestRequiresSlug(t *testing.T) {
	t.Parallel()
	err := cmdTest(context.Background(), slog.Default(), nil)
	if err == nil || !strings.Contains(err.Error(), "missing <slug>") {
		t.Fatalf("got %v, want missing-slug error", err)
	}
}

func TestCmdTestRequiresMode(t *testing.T) {
	t.Parallel()
	err := cmdTest(context.Background(), slog.Default(), []string{"some-slug", "--db=sqlite:///tmp/x.db", "--root=/tmp/x"})
	if err == nil || !strings.Contains(err.Error(), "--against-run") {
		t.Fatalf("got %v, want --against-run-or-latest error", err)
	}
}

func TestCmdTestRejectsBothModes(t *testing.T) {
	t.Parallel()
	err := cmdTest(context.Background(), slog.Default(), []string{"some-slug", "--db=sqlite:///tmp/x.db", "--root=/tmp/x", "--against-run=run_a", "--latest"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("got %v, want mutually-exclusive error", err)
	}
}

func TestReplayInputUsesExactCapturedBytes(t *testing.T) {
	t.Parallel()
	// PostgreSQL JSONB may canonicalise this projection, while migration 0040
	// retains the exact bytes that the original workflow received.
	raw := []byte("{\n  \"b\": 2, \"a\": 1\n}")
	run := journal.RunInfo{
		TriggerMeta:  []byte(`{"a":1,"b":2}`),
		TriggerInput: raw,
	}
	got := replayInputForRun(run)
	if !bytes.Equal(got, raw) {
		t.Fatalf("replay input = %q, want exact captured bytes %q", got, raw)
	}
	got[0] = '['
	if !bytes.Equal(run.TriggerInput, raw) {
		t.Fatal("replay input aliases the journal-owned trigger bytes")
	}
}
