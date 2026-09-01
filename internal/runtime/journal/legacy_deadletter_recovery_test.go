package journal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func seedLegacyDeadLetter(t *testing.T, j *Journal, failedSeqs ...int64) DeadLetterItem {
	t.Helper()
	ctx := context.Background()
	for _, seq := range failedSeqs {
		if _, err := j.RecordStepStartSeq(ctx, "run_1", "send", seq, 1, "idem", "hash"); err != nil {
			t.Fatal(err)
		}
		if err := j.RecordStepEndSeq(ctx, "run_1", "send", seq, 1, nil, "permanent"); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.MoveStepToDeadLetter(ctx, "run_1", "send", "legacy permanent", nil); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	if item.StepSeq != nil || item.StepAttempt != nil {
		t.Fatalf("legacy fixture unexpectedly has exact identity: %+v", item)
	}
	return item
}

func TestLegacyDeadLetterRetryPromotesOnlyUniqueFailedAttempt(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	item := seedLegacyDeadLetter(t, j, 7)

	claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID)
	if err != nil || !claimed {
		t.Fatalf("authorize unique legacy item = %v, %v", claimed, err)
	}
	promoted, err := j.GetDeadLetterItem(ctx, item.ID)
	if err != nil || promoted.StepSeq == nil || *promoted.StepSeq != 7 || promoted.StepAttempt == nil || *promoted.StepAttempt != 1 {
		t.Fatalf("promoted legacy identity = %+v, %v", promoted, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "send", 7)
	if err != nil || state.Status != StatusRedrive {
		t.Fatalf("promoted authorization state = %+v, %v", state, err)
	}
	if run, err := j.GetRun(ctx, "run_1"); err != nil || run.Status != "running" || !run.FinishedAt.IsZero() {
		t.Fatalf("promoted run = %+v, %v", run, err)
	}
}

func TestLegacyDeadLetterRetryRejectsMissingOrAmbiguousIdentityBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name string
		seqs []int64
	}{
		{name: "no matching failed step"},
		{name: "repeated-name failures", seqs: []int64{2, 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j, cleanup := newTestJournal(t)
			defer cleanup()
			ctx := context.Background()
			item := seedLegacyDeadLetter(t, j, tc.seqs...)

			claimed, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID)
			if claimed || !errors.Is(err, ErrLegacyDeadLetterIdentity) {
				t.Fatalf("ambiguous legacy authorization = %v, %v", claimed, err)
			}
			if run, getErr := j.GetRun(ctx, "run_1"); getErr != nil || run.Status != "failed_dlq" || run.FinishedAt.IsZero() {
				t.Fatalf("rejected authorization mutated run = %+v, %v", run, getErr)
			}
			unchanged, getErr := j.GetDeadLetterItem(ctx, item.ID)
			if getErr != nil || unchanged.StepSeq != nil || unchanged.StepAttempt != nil {
				t.Fatalf("rejected authorization promoted item = %+v, %v", unchanged, getErr)
			}
			for _, seq := range tc.seqs {
				state, stateErr := j.LatestStepAttemptSeq(ctx, "run_1", "send", seq)
				if stateErr != nil || state.Status != StatusFailed {
					t.Fatalf("rejected authorization changed step %d = %+v, %v", seq, state, stateErr)
				}
			}
		})
	}
}

func TestDeadLetterRedriveClearsStaleCancellationAuthority(t *testing.T) {
	for _, enqueue := range []bool{false, true} {
		name := "local"
		if enqueue {
			name = "distributed"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			j, cleanup := newTestJournal(t)
			defer cleanup()
			ctx := context.Background()
			item, _ := seedExactRedriveForRecovery(t, j)
			if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`), j.boolValue(true), "run_1"); err != nil {
				t.Fatal(err)
			}

			var claimed bool
			var err error
			if enqueue {
				claimed, err = j.StartDeadLetterRetryQueuedItem(ctx, "run_1", item.ID)
			} else {
				claimed, err = j.StartDeadLetterRetryItem(ctx, "run_1", item.ID)
			}
			if err != nil || !claimed {
				t.Fatalf("fresh redrive authorization = %v, %v", claimed, err)
			}
			flagged, err := j.ListCancelRequestedActive(ctx)
			if err != nil || len(flagged) != 0 {
				t.Fatalf("fresh redrive retained stale cancellation = %v, %v", flagged, err)
			}
			if enqueue {
				leases, err := j.ClaimQueuedRuns(ctx, "fresh-worker", 1, time.Minute)
				if err != nil || len(leases) != 1 || leases[0].RunID != "run_1" {
					t.Fatalf("fresh queued redrive unclaimable = %+v, %v", leases, err)
				}
			} else if run, err := j.GetRun(ctx, "run_1"); err != nil || run.Status != "running" {
				t.Fatalf("fresh local redrive state = %+v, %v", run, err)
			}
		})
	}
}
