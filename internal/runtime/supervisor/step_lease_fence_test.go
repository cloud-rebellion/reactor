package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
)

func TestCachedStepReplyRequiresCurrentLease(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_cached_owned_reply")
	defer cleanup()
	ctx := context.Background()
	if err := j.SetRunStatus(ctx, sup.RunID, "queued"); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].RunID != sup.RunID {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	a := first[0].Owner
	claim, err := j.ClaimOwnedStepAttemptSeq(ctx, sup.RunID, a, "cached", 1, 1, "idem", "hash")
	if err != nil || claim.Attempt != 1 {
		t.Fatalf("first step claim = %+v, %v", claim, err)
	}
	if _, err := j.FinalizeOwnedStepAttemptSeqWithRetryAfter(ctx, sup.RunID, a, "cached", 1, 1, json.RawMessage(`"cached-result"`), "", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := j.ExtendLease(ctx, sup.RunID, a, -time.Minute); err != nil {
		t.Fatal(err)
	}
	frame, err := wire.Wrap(1, 0, wire.KindStepStart, wire.StepStart{
		StepName: "cached", Seq: 1, Attempt: 1, DurableAttempts: true,
		MaxAttempts: 1, IdempotencyKey: "idem", InputHash: "hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	sup.LeaseOwner = a
	var stale bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&stale), writeMu: &sync.Mutex{}}
	if err := d.handleStepStart(ctx, frame); !errors.Is(err, journal.ErrLeaseOwnershipLost) {
		t.Fatalf("expired owner got cached reply: %v", err)
	}
	if stale.Len() != 0 {
		t.Fatal("expired owner received a cached StepReply")
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != sup.RunID {
		t.Fatalf("replacement claim = %+v, %v", second, err)
	}
	sup.LeaseOwner = second[0].Owner
	var current bytes.Buffer
	d = &dispatcher{sup: sup, enc: wire.NewEncoder(&current), writeMu: &sync.Mutex{}}
	if err := d.handleStepStart(ctx, frame); err != nil || current.Len() == 0 {
		t.Fatalf("current owner cached replay = bytes=%d err=%v", current.Len(), err)
	}
}
