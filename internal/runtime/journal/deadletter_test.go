package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestMoveStepToDeadLetterAndGet(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.MoveStepToDeadLetter(ctx, "run_1", "send", "smtp 5xx", json.RawMessage(`{"to":"x@y"}`)); err != nil {
		t.Fatal(err)
	}

	items, err := j.ListDeadLetterItems(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	got := items[0]
	if got.RunID != "run_1" || got.StepName != "send" || got.ErrorText != "smtp 5xx" {
		t.Fatalf("row shape wrong: %+v", got)
	}
	if string(got.Payload) != `{"to":"x@y"}` {
		t.Fatalf("payload = %q, want {\"to\":\"x@y\"}", got.Payload)
	}

	one, err := j.GetDeadLetterItem(ctx, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if one.ID != got.ID {
		t.Fatalf("get returned %+v, want id=%s", one, got.ID)
	}
}

func TestGetDeadLetterMissing(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if _, err := j.GetDeadLetterItem(context.Background(), "dlq_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestGetDeadLetterItemForTenantFencesTheParentRun(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_dlq_acme", "dlq-acme", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_dlq_acme", "wf_dlq_acme", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MoveStepToDeadLetter(ctx, "run_dlq_acme", "send", "private failure", json.RawMessage(`{"private":"payload"}`)); err != nil {
		t.Fatal(err)
	}
	item, err := j.GetDeadLetterItem(ctx, "")
	if err == nil || item.ID != "" {
		t.Fatalf("empty unscoped id = item=%+v err=%v, want not found", item, err)
	}
	items, err := j.ListDeadLetterItemsForTenant(ctx, 1, 0, "acme")
	if err != nil || len(items) != 1 {
		t.Fatalf("list tenant dead letters = %d, err=%v", len(items), err)
	}
	if _, err := j.GetDeadLetterItemForTenant(ctx, items[0].ID, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant lookup = %v, want ErrNotFound", err)
	}
	got, err := j.GetDeadLetterItemForTenant(ctx, items[0].ID, "acme")
	if err != nil || string(got.Payload) != `{"private":"payload"}` {
		t.Fatalf("same tenant lookup = %+v err=%v", got, err)
	}
}

func TestListDeadLetterPagination(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := j.MoveStepToDeadLetter(ctx, "run_1", "send", "boom", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := j.ListDeadLetterItems(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	page2, err := j.ListDeadLetterItems(ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 || len(page2) != 2 {
		t.Fatalf("paging shape wrong: page1=%d page2=%d", len(page1), len(page2))
	}
	if page1[0].ID == page2[0].ID {
		t.Fatal("offset did not advance: page1[0] == page2[0]")
	}
}
