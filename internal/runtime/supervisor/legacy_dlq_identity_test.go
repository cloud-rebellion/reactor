package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bright-interaction/reactor/sdk/wire"
)

func TestLegacyTerminalStepEndKeepsExactRepeatedStepIdentity(t *testing.T) {
	sup, j, closeDB := newTestSupervisorEnv(t, "run_legacy_dlq_identity")
	defer closeDB()
	ctx := context.Background()
	var output bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&output), writeMu: &sync.Mutex{}}

	for _, seq := range []int64{1, 3} {
		if _, err := j.RecordStepStartSeq(ctx, sup.RunID, "A", seq, 1, "idem", "hash"); err != nil {
			t.Fatal(err)
		}
		frame, err := wire.Wrap(seq, 0, wire.KindStepEnd, wire.StepEnd{
			StepName: "A", Seq: seq, Attempt: 1,
			DurableAttempts: false,
			Output:          json.RawMessage("null"),
			ErrorText:       "legacy permanent failure",
			Retryable:       false,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.handleStepEnd(ctx, frame); err != nil {
			t.Fatalf("legacy step_end seq %d: %v", seq, err)
		}
	}

	items, err := j.ListDeadLetterItems(ctx, 10, 0)
	if err != nil || len(items) != 2 {
		t.Fatalf("legacy repeated-step DLQ = %+v, %v", items, err)
	}
	seen := map[int64]bool{}
	for _, item := range items {
		if item.StepName != "A" || item.StepSeq == nil || item.StepAttempt == nil || *item.StepAttempt != 1 {
			t.Fatalf("legacy DLQ lost exact identity: %+v", item)
		}
		seen[*item.StepSeq] = true
	}
	if !seen[1] || !seen[3] {
		t.Fatalf("legacy repeated-step seq identities = %v; want 1 and 3", seen)
	}
}

func TestLegacyNullableRedriveStartFailureRestoresFailedDLQ(t *testing.T) {
	sup, j, closeDB := newTestSupervisorEnv(t, "run_legacy_redrive_start")
	defer closeDB()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, sup.RunID, "send", 4, 1, "idem", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, sup.RunID, "send", 4, 1, nil, "legacy permanent"); err != nil {
		t.Fatal(err)
	}
	if err := j.MoveStepToDeadLetter(ctx, sup.RunID, "send", "legacy permanent", nil); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, sup.RunID, "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, sup.RunID)
	if err != nil || item.StepSeq != nil || item.StepAttempt != nil {
		t.Fatalf("legacy nullable item = %+v, %v", item, err)
	}
	claimed, err := j.StartDeadLetterRetryItem(ctx, sup.RunID, item.ID)
	if err != nil || !claimed {
		t.Fatalf("authorize legacy nullable item = %v, %v", claimed, err)
	}

	sup.BinaryPath = filepath.Join(t.TempDir(), "missing-workflow")
	status, runErr := sup.Run(ctx)
	if runErr == nil || status != "failed_dlq" {
		t.Fatalf("legacy redrive start failure = status %q err %v", status, runErr)
	}
	if run, err := j.GetRun(ctx, sup.RunID); err != nil || run.Status != "failed_dlq" || run.FinishedAt.IsZero() {
		t.Fatalf("legacy redrive start recovery = %+v, %v", run, err)
	}
	promoted, err := j.GetDeadLetterItem(ctx, item.ID)
	if err != nil || promoted.StepSeq == nil || *promoted.StepSeq != 4 || promoted.StepAttempt == nil || *promoted.StepAttempt != 1 {
		t.Fatalf("legacy redrive identity after start failure = %+v, %v", promoted, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, sup.RunID, "send", 4)
	if err != nil || state.Status != "failed" {
		t.Fatalf("legacy redrive attempt after start failure = %+v, %v", state, err)
	}
	claimed, err = j.StartDeadLetterRetryItem(ctx, sup.RunID, item.ID)
	if err != nil || !claimed {
		t.Fatalf("legacy redrive not retryable after start failure = %v, %v", claimed, err)
	}
	if errors.Is(runErr, context.Canceled) {
		t.Fatalf("start failure misclassified as operator cancellation: %v", runErr)
	}
}
