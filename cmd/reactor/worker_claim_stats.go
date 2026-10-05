package main

import (
	"database/sql"
	"log/slog"
	"time"
)

// Claim durations include candidate selection, tenant admission, row locks,
// lease writes, and commit. These process-local counters are owned by the
// worker poll loop and do not add work to the claim transaction itself.
type workerClaimStats struct {
	attempts  uint64
	empty     uint64
	errors    uint64
	cancelled uint64
	claimed   uint64
	max       time.Duration
	buckets   [10]uint64
}

var workerClaimLatencyBounds = [...]time.Duration{
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	5 * time.Second,
}

func (s *workerClaimStats) record(duration time.Duration, claimed int, err error, cancelled bool) {
	if duration < 0 {
		duration = 0
	}
	s.attempts++
	if duration > s.max {
		s.max = duration
	}
	switch {
	case cancelled:
		s.cancelled++
	case err != nil:
		s.errors++
	case claimed == 0:
		s.empty++
	case claimed > 0:
		s.claimed += uint64(claimed)
	}
	for i, bound := range workerClaimLatencyBounds {
		if duration <= bound {
			s.buckets[i]++
			return
		}
	}
	s.buckets[len(s.buckets)-1]++
}

type workerClaimLatencyBuckets struct {
	LE5ms    uint64 `json:"le_5ms"`
	LE10ms   uint64 `json:"le_10ms"`
	LE25ms   uint64 `json:"le_25ms"`
	LE50ms   uint64 `json:"le_50ms"`
	LE100ms  uint64 `json:"le_100ms"`
	LE250ms  uint64 `json:"le_250ms"`
	LE500ms  uint64 `json:"le_500ms"`
	LE1000ms uint64 `json:"le_1000ms"`
	LE5000ms uint64 `json:"le_5000ms"`
	LEInf    uint64 `json:"le_inf"`
}

func (s workerClaimStats) cumulativeBuckets() workerClaimLatencyBuckets {
	var cumulative [10]uint64
	var total uint64
	for i, n := range s.buckets {
		total += n
		cumulative[i] = total
	}
	return workerClaimLatencyBuckets{
		LE5ms: cumulative[0], LE10ms: cumulative[1], LE25ms: cumulative[2],
		LE50ms: cumulative[3], LE100ms: cumulative[4], LE250ms: cumulative[5],
		LE500ms: cumulative[6], LE1000ms: cumulative[7], LE5000ms: cumulative[8],
		LEInf: cumulative[9],
	}
}

// log includes this worker's own SQL pool. The daemon's /metrics endpoint
// observes a different process and cannot show whether worker claims wait for
// a connection before their candidate query starts.
func (s workerClaimStats) log(log *slog.Logger, workerID, reason string, pool sql.DBStats) {
	log.Info("worker: claim latency summary",
		"worker_id", workerID,
		"reason", reason,
		"attempts_total", s.attempts,
		"empty_total", s.empty,
		"errors_total", s.errors,
		"cancelled_total", s.cancelled,
		"runs_claimed_total", s.claimed,
		"duration_max_seconds", s.max.Seconds(),
		"duration_buckets_total", s.cumulativeBuckets(),
		"db_pool_max_open_connections", pool.MaxOpenConnections,
		"db_pool_open_connections", pool.OpenConnections,
		"db_pool_in_use_connections", pool.InUse,
		"db_pool_idle_connections", pool.Idle,
		"db_pool_wait_total", pool.WaitCount,
		"db_pool_wait_seconds_total", pool.WaitDuration.Seconds(),
	)
}
