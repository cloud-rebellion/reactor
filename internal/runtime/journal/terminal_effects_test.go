package journal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTerminalEffectClaimReleaseAndAck(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, "run_1", StatusSucceeded); err != nil {
		t.Fatal(err)
	}
	effects, err := j.ClaimTerminalEffects(ctx, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(effects) != 1 || effects[0].RunID != "run_1" || effects[0].Status != StatusSucceeded {
		t.Fatalf("claimed effects = %+v", effects)
	}
	event, err := j.GetTerminalEffectEvent(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if event.WorkflowSlug != "demo" || event.Status != StatusSucceeded || event.TriggerKind != "manual" {
		t.Fatalf("event = %+v", event)
	}
	if err := j.ReleaseTerminalEffect(ctx, "run_1", "temporary sender outage"); err != nil {
		t.Fatal(err)
	}
	if effects, err = j.ClaimTerminalEffects(ctx, 10, time.Minute); err != nil || len(effects) != 1 {
		t.Fatalf("released effect was not reclaimable: %+v, %v", effects, err)
	}
	if err := j.MarkTerminalEffectDelivered(ctx, "run_1"); err != nil {
		t.Fatal(err)
	}
	if effects, err = j.ClaimTerminalEffects(ctx, 10, time.Minute); err != nil || len(effects) != 0 {
		t.Fatalf("acknowledged effect was reclaimed: %+v, %v", effects, err)
	}
}

func TestDryRunDoesNotCreateTerminalEffect(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MarkRunFinishedForMode(ctx, "run_1", StatusSucceeded, true); err != nil {
		t.Fatal(err)
	}
	effects, err := j.ClaimTerminalEffects(ctx, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(effects) != 0 {
		t.Fatalf("dry run created terminal effects: %+v", effects)
	}
}

func TestTerminalEffectRefreshesUnacknowledgedStatus(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, "run_1", StatusSucceeded); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimTerminalEffects(ctx, 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	// A recovery/retry transition can produce a different terminal status for
	// the same durable run id before the first effect was acknowledged.
	if err := j.SetRunStatus(ctx, "run_1", "running"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed"); err != nil {
		t.Fatal(err)
	}
	effects, err := j.ClaimTerminalEffects(ctx, 1, time.Minute)
	if err != nil || len(effects) != 1 || effects[0].Status != "failed" {
		t.Fatalf("refreshed effects = %+v, %v", effects, err)
	}
}

func TestTerminalEffectClaimFenceProtectsSameStatusRetryGeneration(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	old, err := j.ClaimTerminalEffect(ctx, "run_1", "failed_dlq", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// A retry reuses the run id and status, but resets the receipt claim. This
	// is the same durable transition performed by StartDeadLetterRetryItem.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE terminal_effects
		SET attempts = 0, claimed_at = NULL, claim_token = NULL, delivered_at = NULL, last_error = NULL, created_at = $1
		WHERE run_id = $2`), j.now(), "run_1"); err != nil {
		t.Fatal(err)
	}
	newClaim, err := j.ClaimTerminalEffect(ctx, "run_1", "failed_dlq", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, old); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("stale acknowledgement = %v, want ErrTerminalEffectClaimLost", err)
	}
	if err := j.ReleaseTerminalEffectForClaim(ctx, old, "late old handler"); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("stale release = %v, want ErrTerminalEffectClaimLost", err)
	}
	if err := j.MarkTerminalEffectDeliveredForClaim(ctx, newClaim); err != nil {
		t.Fatalf("new generation acknowledgement: %v", err)
	}
}

func TestTerminalEffectDirectClaimRejectsReopenedRun(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_1", "running"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimTerminalEffect(ctx, "run_1", "failed_dlq", time.Minute); !errors.Is(err, ErrTerminalEffectClaimLost) {
		t.Fatalf("claim for reopened run = %v, want ErrTerminalEffectClaimLost", err)
	}
}

func TestTerminalEffectEventBoundsUntrustedErrorSummary(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.RecordStepStart(ctx, "run_1", "send", 1, "", ""); err != nil {
		t.Fatal(err)
	}
	longError := strings.Repeat("é", maxTerminalEffectErrorBytes)
	if err := j.RecordStepEnd(ctx, "run_1", "send", 1, nil, longError); err != nil {
		t.Fatal(err)
	}

	event, err := j.GetTerminalEffectEvent(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(event.ErrorText) > maxTerminalEffectErrorBytes {
		t.Fatalf("terminal error summary is %d bytes, want <= %d", len(event.ErrorText), maxTerminalEffectErrorBytes)
	}
	if !utf8.ValidString(event.ErrorText) {
		t.Fatal("terminal error summary is invalid UTF-8")
	}
	if !strings.HasSuffix(event.ErrorText, terminalEffectErrorTruncatedSuffix) {
		t.Fatalf("terminal error summary lacks truncation marker: %q", event.ErrorText)
	}
}
