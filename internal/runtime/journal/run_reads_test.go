package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestGetRunForTenantMetadataBoundsTriggerMeta(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const workflowID = "wf_bounded_metadata"
	if err := j.CreateWorkflowInTenant(ctx, workflowID, "bounded-metadata", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"body":"` + strings.Repeat("x", 128) + `"}`)
	if err := j.CreateRun(ctx, "run_bounded_metadata", workflowID, "manual", meta); err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-migration row whose exact trigger_input column is absent;
	// the bounded receipt must use trigger_meta for its durable size.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET trigger_input = NULL WHERE id = $1`), "run_bounded_metadata"); err != nil {
		t.Fatal(err)
	}

	got, err := j.GetRunForTenantMetadata(ctx, "run_bounded_metadata", "acme", 16)
	if err != nil {
		t.Fatal(err)
	}
	if got.TriggerInput != nil || len(got.TriggerMeta) != 0 {
		t.Fatalf("bounded metadata materialized input/meta: input=%d meta=%d", len(got.TriggerInput), len(got.TriggerMeta))
	}
	if got.TriggerMetaBytes != len(meta) {
		t.Fatalf("metadata bytes = %d, want %d", got.TriggerMetaBytes, len(meta))
	}
	if got.TriggerInputBytes != len(meta) || got.TriggerInputPresent {
		t.Fatalf("legacy input receipt = %d/present=%t, want %d/false", got.TriggerInputBytes, got.TriggerInputPresent, len(meta))
	}
	if _, err := j.GetRunForTenantMetadata(ctx, "run_bounded_metadata", "globex", 16); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign metadata read = %v, want ErrNotFound", err)
	}
}

func TestGetRunForTenantInputBoundedRefusesOversizedAndPreservesExactBytes(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const workflowID = "wf_bounded_input"
	if err := j.CreateWorkflowInTenant(ctx, workflowID, "bounded-input", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	large := []byte(`{"value":"` + strings.Repeat("x", 512) + `"}`)
	if err := j.CreateRun(ctx, "run_bounded_input_large", workflowID, "manual", large); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetRunForTenantInputBounded(ctx, "run_bounded_input_large", "acme", 64); !errors.Is(err, ErrRunInputTooLarge) {
		t.Fatalf("oversized input read = %v, want ErrRunInputTooLarge", err)
	}

	exact := []byte(` {"value": "exact", "n": 2} `)
	if err := j.CreateRun(ctx, "run_bounded_input_exact", workflowID, "manual", exact); err != nil {
		t.Fatal(err)
	}
	got, err := j.GetRunForTenantInputBounded(ctx, "run_bounded_input_exact", "acme", len(exact))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ExecutionInput()) != string(exact) {
		t.Fatalf("bounded input changed bytes: got %q want %q", got.ExecutionInput(), exact)
	}
	if got.TriggerInputBytes != len(exact) || !got.TriggerInputPresent {
		t.Fatalf("exact input receipt = %d/present=%t, want %d/true", got.TriggerInputBytes, got.TriggerInputPresent, len(exact))
	}
	// A malformed/imported row may carry a small exact input beside an
	// oversized metadata projection. The bounded helper must not materialize
	// that unrelated column while reading the execution bytes.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET trigger_meta = $1 WHERE id = $2`), strings.Repeat("m", 1024), "run_bounded_input_exact"); err != nil {
		t.Fatal(err)
	}
	got, err = j.GetRunForTenantInputBounded(ctx, "run_bounded_input_exact", "acme", len(exact))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ExecutionInput()) != string(exact) || len(got.TriggerMeta) != 0 || got.TriggerMetaBytes != 1024 {
		t.Fatalf("bounded malformed row = input %q meta=%d/%d", got.ExecutionInput(), len(got.TriggerMeta), got.TriggerMetaBytes)
	}
	if _, err := j.GetRunForTenantInputBounded(ctx, "run_bounded_input_exact", "globex", len(exact)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign input read = %v, want ErrNotFound", err)
	}
	if err := j.CreateRun(ctx, "run_bounded_input_empty", workflowID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET trigger_input = $1 WHERE id = $2`), []byte{}, "run_bounded_input_empty"); err != nil {
		t.Fatal(err)
	}
	empty, err := j.GetRunForTenantInputBounded(ctx, "run_bounded_input_empty", "acme", 1)
	if err != nil {
		t.Fatal(err)
	}
	if empty.TriggerInput == nil || len(empty.TriggerInput) != 0 || empty.ExecutionInput() == nil || len(empty.ExecutionInput()) != 0 || !empty.TriggerInputPresent {
		t.Fatalf("exact empty input lost legacy distinction: input=%#v present=%t", empty.TriggerInput, empty.TriggerInputPresent)
	}
	if _, err := j.GetRunForTenantInputBounded(ctx, "run_bounded_input_exact", "acme", 17<<20); err == nil {
		t.Fatal("expected an excessive direct input bound to be rejected")
	}
}
