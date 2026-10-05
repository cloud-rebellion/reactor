package journal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFindRecordedCallBySeqDistinguishesStepAndWait(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.RecordStepStartSeq(ctx, "run_1", "charge", 1, 1, "idem", "hash"); err != nil {
		t.Fatal(err)
	}
	call, err := j.FindRecordedCallBySeq(ctx, "run_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if call.Kind != RecordedCallStep || call.StepName != "charge" {
		t.Fatalf("step checkpoint = %+v, want step/charge", call)
	}

	if _, err := j.ScheduleSleepSeq(ctx, "run_1", "wait", 2, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	call, err = j.FindRecordedCallBySeq(ctx, "run_1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if call.Kind != KindSleep || call.StepName != "wait" {
		t.Fatalf("sleep checkpoint = %+v, want sleep/wait", call)
	}
}

func TestFindRecordedCallBySeqFailsClosedOnKindConflict(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.RecordStepStartSeq(ctx, "run_1", "charge", 3, 1, "idem", "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSleepSeq(ctx, "run_1", "wait", 3, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.FindRecordedCallBySeq(ctx, "run_1", 3); !errors.Is(err, ErrRecordedCallConflict) {
		t.Fatalf("conflicting checkpoint err = %v, want ErrRecordedCallConflict", err)
	}
}
