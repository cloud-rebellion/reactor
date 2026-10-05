package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

const (
	// ReapExpiredLeases limits each database transaction to 128 leases. The
	// leader may run several of those bounded transactions in one pass so a
	// failed fleet does not recover at only one batch per housekeeping tick.
	leaderLeaseReapMaxBatches      = 8
	leaderLeaseReapPassTimeout     = 30 * time.Second
	leaderLeaseReapIdleInterval    = 20 * time.Second
	leaderLeaseReapBacklogInterval = time.Second
)

type leaderLeaseReaper interface {
	ReapExpiredLeases(context.Context) (int64, error)
}

type expiredLeaseProbe func(context.Context) (bool, error)

// expiredRunLeaseExists uses the expiry index to check for remaining work.
// ReapExpiredLeases returns the number of runs requeued, not the number of
// leases consumed: cancelled and terminal runs may also have expired leases.
func expiredRunLeaseExists(db *sql.DB) expiredLeaseProbe {
	return func(ctx context.Context) (bool, error) {
		var exists bool
		err := db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM leases WHERE expires_at < $1)`, time.Now().UTC()).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("check expired run leases: %w", err)
		}
		return exists, nil
	}
}

// drainExpiredRunLeases performs at most eight capped journal transactions.
// Worker reapers may run concurrently: PostgreSQL SKIP LOCKED and the
// journal's exact lease-generation fence ensure they cannot requeue the same
// generation twice. A remaining backlog is revisited promptly by the leader
// loop, without turning one leadership pass into an unbounded transaction.
func drainExpiredRunLeases(ctx context.Context, log *slog.Logger, reaper leaderLeaseReaper, hasExpired expiredLeaseProbe) (bool, error) {
	passCtx, cancel := context.WithTimeout(ctx, leaderLeaseReapPassTimeout)
	defer cancel()
	var requeued int64
	for batch := 0; batch < leaderLeaseReapMaxBatches; batch++ {
		pending, err := hasExpired(passCtx)
		if err != nil {
			return false, err
		}
		if !pending {
			if requeued > 0 {
				log.Info("serve: requeued expired worker runs", "count", requeued, "more_expired", false)
			}
			return false, nil
		}
		n, err := reaper.ReapExpiredLeases(passCtx)
		if err != nil {
			return false, fmt.Errorf("reap expired run leases: %w", err)
		}
		requeued += n
	}
	pending, err := hasExpired(passCtx)
	if err != nil {
		return false, err
	}
	if requeued > 0 || pending {
		log.Info("serve: expired worker lease recovery pass", "requeued", requeued, "more_expired", pending)
	}
	return pending, nil
}

// runLeaderLeaseReaper continues the first pass made synchronously after
// leadership acquisition. It remains active even when the autoscaler has
// scaled to zero or every worker process has crashed. An unexpected probe or
// reaper failure exits this component so runLeaderTasks withdraws readiness.
func runLeaderLeaseReaper(ctx context.Context, log *slog.Logger, reaper leaderLeaseReaper, hasExpired expiredLeaseProbe, backlog bool) error {
	next := leaderLeaseReapIdleInterval
	if backlog {
		next = leaderLeaseReapBacklogInterval
	}
	timer := time.NewTimer(next)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			more, err := drainExpiredRunLeases(ctx, log, reaper, hasExpired)
			if err != nil {
				return err
			}
			next = leaderLeaseReapIdleInterval
			if more {
				next = leaderLeaseReapBacklogInterval
			}
			timer.Reset(next)
		}
	}
}
