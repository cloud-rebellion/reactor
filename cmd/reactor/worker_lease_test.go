package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestWorkerRejectsNonPositiveLeaseTTLBeforeStartup(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := cmdWorker(context.Background(), log, []string{
		"--db", "postgres://unused.invalid/reactor",
		"--lease-ttl", "0s",
	})
	if err == nil || !strings.Contains(err.Error(), "--lease-ttl must be greater than zero") {
		t.Fatalf("zero lease ttl error = %v", err)
	}
}

type heartbeatJournalStub struct {
	extendErr error
	status    string
}

func (s heartbeatJournalStub) ExtendLease(context.Context, string, string, time.Duration) error {
	return s.extendErr
}

func (s heartbeatJournalStub) GetRun(context.Context, string) (journal.RunInfo, error) {
	return journal.RunInfo{ID: "run", Status: s.status}, nil
}

func TestHeartbeatOwnershipLossCancelsChildContext(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "running"},
		"run", "owner-a", 15*time.Millisecond, cancelExec,
	)
	if !errors.Is(err, errLeaseHeartbeatUnsafe) {
		t.Fatalf("heartbeat error = %v, want unsafe sentinel", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("execution cancellation cause = %v, want lease heartbeat loss", cause)
	}
}

func TestHeartbeatReapedQueuedLeaseCancelsStaleChild(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "queued"},
		"run", "stale-owner", 15*time.Millisecond, cancelExec,
	)
	if !errors.Is(err, errLeaseHeartbeatUnsafe) {
		t.Fatalf("reaped heartbeat error = %v, want unsafe sentinel", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("stale execution cancellation cause = %v, want lease heartbeat loss", cause)
	}
}

func TestHeartbeatReplacementFinishedFirstStillCancelsStaleChild(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "succeeded"},
		"run", "owner-a", 15*time.Millisecond, cancelExec,
	)
	if err != nil {
		t.Fatalf("replacement terminal heartbeat race = %v, want normal logged stop", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("replacement terminal left stale execution alive: %v", cause)
	}
}

func TestHeartbeatReaperCancellationStopsPossiblyLiveOldChild(t *testing.T) {
	execCtx, cancelExec := context.WithCancelCause(context.Background())
	defer cancelExec(context.Canceled)
	err := heartbeatLease(
		context.Background(),
		heartbeatJournalStub{extendErr: journal.ErrLeaseOwnershipLost, status: "cancelled"},
		"run", "expired-owner", 15*time.Millisecond, cancelExec,
	)
	if err != nil {
		t.Fatalf("cancelled heartbeat race = %v, want normal terminal stop", err)
	}
	if cause := context.Cause(execCtx); !errors.Is(cause, errLeaseHeartbeatUnsafe) {
		t.Fatalf("cancelled stale child cause = %v, want lease heartbeat loss", cause)
	}
}
