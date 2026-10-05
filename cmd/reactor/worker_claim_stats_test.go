package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestWorkerClaimStatsCountsEveryPollAndCumulativeLatency(t *testing.T) {
	var stats workerClaimStats
	stats.record(3*time.Millisecond, 0, nil, false)
	stats.record(12*time.Millisecond, 2, nil, false)
	stats.record(300*time.Millisecond, 0, errors.New("database unavailable"), false)
	stats.record(6*time.Second, 0, context.Canceled, true)

	if stats.attempts != 4 || stats.empty != 1 || stats.errors != 1 || stats.cancelled != 1 || stats.claimed != 2 {
		t.Fatalf("claim outcomes = %+v", stats)
	}
	if stats.max != 6*time.Second {
		t.Fatalf("max duration = %s, want 6s", stats.max)
	}
	b := stats.cumulativeBuckets()
	if b.LE5ms != 1 || b.LE10ms != 1 || b.LE25ms != 2 || b.LE250ms != 2 || b.LE500ms != 3 || b.LE5000ms != 3 || b.LEInf != 4 {
		t.Fatalf("cumulative latency buckets = %+v", b)
	}
	if b.LEInf != stats.attempts {
		t.Fatalf("last bucket = %d, attempts = %d", b.LEInf, stats.attempts)
	}
}

func TestWorkerClaimStatsSummaryIsStructuredAndCumulative(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, nil))
	var stats workerClaimStats
	stats.record(8*time.Millisecond, 1, nil, false)
	stats.log(log, "worker-a", "periodic", sql.DBStats{
		MaxOpenConnections: 8, OpenConnections: 8, InUse: 7, Idle: 1,
		WaitCount: 3, WaitDuration: 150 * time.Millisecond,
	})

	var event struct {
		WorkerID        string                    `json:"worker_id"`
		Reason          string                    `json:"reason"`
		Attempts        uint64                    `json:"attempts_total"`
		Claimed         uint64                    `json:"runs_claimed_total"`
		DurationBuckets workerClaimLatencyBuckets `json:"duration_buckets_total"`
		PoolMaxOpen     int                       `json:"db_pool_max_open_connections"`
		PoolInUse       int                       `json:"db_pool_in_use_connections"`
		PoolWaits       int64                     `json:"db_pool_wait_total"`
		PoolWaitSeconds float64                   `json:"db_pool_wait_seconds_total"`
	}
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if event.WorkerID != "worker-a" || event.Reason != "periodic" || event.Attempts != 1 || event.Claimed != 1 || event.DurationBuckets.LE5ms != 0 || event.DurationBuckets.LE10ms != 1 || event.DurationBuckets.LEInf != 1 || event.PoolMaxOpen != 8 || event.PoolInUse != 7 || event.PoolWaits != 3 || event.PoolWaitSeconds != 0.15 {
		t.Fatalf("summary = %+v", event)
	}
}
