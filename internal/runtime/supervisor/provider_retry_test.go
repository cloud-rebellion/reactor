package supervisor

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
)

func TestProviderRetryWindowSurvivesStepEndAckAndFreshStart(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_provider_retry_window")
	defer cleanup()
	ctx := context.Background()
	first, err := j.ClaimStepAttemptSeq(ctx, sup.RunID, "provider-read", 1, 3, "idem", "hash")
	if err != nil || first.Attempt != 1 {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	var out bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), writeMu: &sync.Mutex{}}
	tooLong, err := wire.Wrap(9, 0, wire.KindStepEnd, wire.StepEnd{
		StepName: "provider-read", Seq: 1, Attempt: 1, DurableAttempts: true,
		ErrorText: "HTTP 429", Retryable: true, RetryAfterMs: 30001,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handleStepEnd(ctx, tooLong); err == nil {
		t.Fatal("unbounded provider retry delay was acknowledged")
	}
	if state, err := j.LatestStepAttemptSeq(ctx, sup.RunID, "provider-read", 1); err != nil || state.Status != journal.StatusRunning {
		t.Fatalf("invalid hint changed attempt = %+v, %v", state, err)
	}
	end, err := wire.Wrap(1, 0, wire.KindStepEnd, wire.StepEnd{
		StepName: "provider-read", Seq: 1, Attempt: 1, DurableAttempts: true,
		ErrorText: "HTTP 429", Retryable: true, RetryAfterMs: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handleStepEnd(ctx, end); err != nil {
		t.Fatal(err)
	}
	ack, err := wire.NewDecoder(&out).Decode()
	if err != nil || ack.Kind != wire.KindAck {
		t.Fatalf("step end ack = %+v, %v", ack, err)
	}
	state, err := j.LatestStepAttemptSeq(ctx, sup.RunID, "provider-read", 1)
	if err != nil || state.Status != journal.StatusRetrying || state.RetryNotBefore.Before(time.Now().Add(4*time.Second)) {
		t.Fatalf("provider deadline after ack = %+v, %v", state, err)
	}

	out.Reset()
	start, err := wire.Wrap(2, 0, wire.KindStepStart, wire.StepStart{
		StepName: "provider-read", Seq: 1, Attempt: 1, DurableAttempts: true,
		MaxAttempts: 3, IdempotencyKey: "idem", InputHash: "hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	var body wire.StepStart
	if err := wire.Unwrap(start, &body); err != nil {
		t.Fatal(err)
	}
	if err := d.handleDurableStepStart(ctx, start, body); err != nil {
		t.Fatal(err)
	}
	reply, err := wire.NewDecoder(&out).Decode()
	if err != nil || reply.Kind != wire.KindStepReply {
		t.Fatalf("fresh start reply = %+v, %v", reply, err)
	}
	var verdict wire.StepReply
	if err := wire.Unwrap(reply, &verdict); err != nil || verdict.RetryWaitMs <= 0 || verdict.Attempt != 0 {
		t.Fatalf("fresh start verdict = %+v, %v; want wait before claim", verdict, err)
	}
	if count, err := j.AttemptCountSeq(ctx, sup.RunID, "provider-read", 1); err != nil || count != 1 {
		t.Fatalf("attempt count while waiting = %d, %v; want 1", count, err)
	}
}
