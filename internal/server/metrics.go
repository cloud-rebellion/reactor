package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

// Metrics is the lightweight counter set the daemon exposes at /metrics
// in Prometheus text format. Kept stdlib-only (no client_golang dep) so
// the binary stays small; a real Prometheus scraper happily ingests the
// hand-rolled text exposition format.
//
// Operators wire MetricsCounter fields into the dispatcher / rotators /
// MCP so increments land in the right gauge. Lock-free atomic adds keep
// the hot path off the scrape goroutine.
type Metrics struct {
	RunsStarted   atomic.Uint64
	RunsSucceeded atomic.Uint64
	RunsFailed    atomic.Uint64
	RunsDLQ       atomic.Uint64
	RotationsRun  atomic.Uint64
	RotationsErr  atomic.Uint64
	MCPCalls      atomic.Uint64
	WebhookCalls  atomic.Uint64

	// QueueDepth and WorkerCapacity are short, read-only probes wired by the
	// daemon. They are kept as callbacks so the metrics package stays decoupled
	// from the journal implementation and embedded servers can omit them. A
	// failed probe is exported as -1 with reactor_capacity_probe_ok=0 rather
	// than being reported as a misleading zero.
	QueueDepth     func(context.Context) (int, error)
	QueueClaimable func(context.Context) (int, error)
	QueueOldestAge func(context.Context) (time.Duration, error)
	WorkerCapacity func(context.Context, time.Duration) (count, capacity int, err error)
	// DBPoolStats is a point-in-time pool snapshot. Connection pressure is a
	// separate capacity signal from queue depth: adding workers cannot help
	// when the database pool is already waiting for a free connection.
	DBPoolStats func() sql.DBStats

	startedAt time.Time
}

// NewMetrics constructs a Metrics with startedAt = now so uptime
// renders correctly from the first scrape.
func NewMetrics() *Metrics {
	return &Metrics{startedAt: time.Now()}
}

// IncRunsStarted implements dispatcher.Counters.
func (m *Metrics) IncRunsStarted() { m.RunsStarted.Add(1) }

// IncRunsTerminal implements dispatcher.Counters; status maps to the
// right gauge (succeeded / failed / failed_dlq are the meaningful
// values dispatcher sees, suspended is in-flight not terminal).
func (m *Metrics) IncRunsTerminal(status string) {
	switch status {
	case "succeeded":
		m.RunsSucceeded.Add(1)
	case "failed_dlq":
		m.RunsDLQ.Add(1)
	default:
		m.RunsFailed.Add(1)
	}
}

// IncMCPCall implements the MCP transport's optional call-counter surface.
// The counter is deliberately incremented at the tools/call dispatch boundary
// so failed validation and execution attempts remain visible to operators.
func (m *Metrics) IncMCPCall() { m.MCPCalls.Add(1) }

// metrics handles GET /metrics in the Prometheus text exposition format
// (https://prometheus.io/docs/instrumenting/exposition_formats/).
// Returns 503 when no Metrics is wired (server constructed without it).
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if s.Metrics == nil {
		http.Error(w, "metrics not wired", http.StatusServiceUnavailable)
		return
	}
	m := s.Metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	mem := runtime.MemStats{}
	runtime.ReadMemStats(&mem)
	uptimeSeconds := time.Since(m.startedAt).Seconds()

	write := func(name, help, kind string, value uint64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %s\n",
			name, help, name, kind, name, strconv.FormatUint(value, 10))
	}
	writeFloat := func(name, help, kind string, value float64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %g\n",
			name, help, name, kind, name, value)
	}

	write("reactor_runs_started_total", "Total run dispatches.", "counter", m.RunsStarted.Load())
	write("reactor_runs_succeeded_total", "Total runs that terminated with status=succeeded.", "counter", m.RunsSucceeded.Load())
	write("reactor_runs_failed_total", "Total runs that terminated with status=failed.", "counter", m.RunsFailed.Load())
	write("reactor_runs_dlq_total", "Total runs that terminated with status=failed_dlq.", "counter", m.RunsDLQ.Load())
	write("reactor_rotations_run_total", "Total credential rotations attempted.", "counter", m.RotationsRun.Load())
	write("reactor_rotations_error_total", "Total rotation attempts that errored.", "counter", m.RotationsErr.Load())
	write("reactor_mcp_calls_total", "Total MCP tool invocations across stdio + HTTP transports.", "counter", m.MCPCalls.Load())
	write("reactor_webhook_calls_total", "Total inbound webhook deliveries.", "counter", m.WebhookCalls.Load())
	queued, workers, capacity := -1, -1, -1
	probeOK := 1
	probeCtx, cancelProbe := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancelProbe()
	if m.QueueDepth == nil {
		probeOK = 0
	} else if n, err := m.QueueDepth(probeCtx); err != nil {
		probeOK = 0
	} else {
		queued = n
	}
	if m.WorkerCapacity == nil {
		probeOK = 0
	} else if n, cap, err := m.WorkerCapacity(probeCtx, 30*time.Second); err != nil {
		probeOK = 0
	} else {
		workers, capacity = n, cap
	}
	writeFloat("reactor_queue_depth", "Uncancelled queued runs, including policy-blocked backlog; -1 means the capacity probe failed.", "gauge", float64(queued))
	writeFloat("reactor_worker_count", "Active distributed workers seen within the heartbeat window; -1 means the capacity probe failed.", "gauge", float64(workers))
	writeFloat("reactor_worker_capacity", "Summed concurrency of active distributed workers; -1 means the capacity probe failed.", "gauge", float64(capacity))
	writeFloat("reactor_capacity_probe_ok", "Whether queue and worker capacity probes completed successfully (1 or 0).", "gauge", float64(probeOK))
	claimable, claimableProbeOK := -1, 0
	if m.QueueClaimable != nil {
		claimableCtx, cancelClaimable := context.WithTimeout(r.Context(), 500*time.Millisecond)
		n, err := m.QueueClaimable(claimableCtx)
		cancelClaimable()
		if err == nil {
			claimable, claimableProbeOK = n, 1
		}
	}
	writeFloat("reactor_queue_claimable_depth", "Queued runs currently admissible under workflow and tenant policy; -1 means the probe failed.", "gauge", float64(claimable))
	writeFloat("reactor_queue_claimable_probe_ok", "Whether the policy-aware queued-run probe completed successfully (1 or 0).", "gauge", float64(claimableProbeOK))
	queueAge, queueAgeProbeOK := -1.0, 0.0
	if m.QueueOldestAge != nil {
		ageCtx, cancelAge := context.WithTimeout(r.Context(), 500*time.Millisecond)
		age, err := m.QueueOldestAge(ageCtx)
		cancelAge()
		if err == nil && age >= 0 {
			queueAge, queueAgeProbeOK = age.Seconds(), 1
		}
	}
	writeFloat("reactor_queue_oldest_age_seconds", "Age of the oldest uncancelled queued run; zero means no backlog and -1 means the probe failed.", "gauge", queueAge)
	writeFloat("reactor_queue_age_probe_ok", "Whether the oldest queued run age probe completed successfully (1 or 0).", "gauge", queueAgeProbeOK)
	if m.DBPoolStats != nil {
		stats := m.DBPoolStats()
		writeFloat("reactor_db_pool_max_open_connections", "Configured maximum open database connections; zero means unlimited.", "gauge", float64(stats.MaxOpenConnections))
		writeFloat("reactor_db_pool_open_connections", "Open database connections.", "gauge", float64(stats.OpenConnections))
		writeFloat("reactor_db_pool_in_use_connections", "Database connections currently in use.", "gauge", float64(stats.InUse))
		writeFloat("reactor_db_pool_idle_connections", "Idle database connections.", "gauge", float64(stats.Idle))
		write("reactor_db_pool_wait_total", "Cumulative waits for a database connection.", "counter", uint64(stats.WaitCount))
		writeFloat("reactor_db_pool_wait_seconds_total", "Cumulative time waiting for a database connection, in seconds.", "counter", stats.WaitDuration.Seconds())
	}
	writeFloat("reactor_uptime_seconds", "Daemon uptime in seconds.", "gauge", uptimeSeconds)
	writeFloat("reactor_goroutines", "Live goroutines.", "gauge", float64(runtime.NumGoroutine()))
	writeFloat("reactor_memory_alloc_bytes", "Bytes allocated and still in use.", "gauge", float64(mem.Alloc))
	writeFloat("reactor_memory_sys_bytes", "Bytes of memory obtained from the OS.", "gauge", float64(mem.Sys))
	writeFloat("reactor_memory_gc_cycles_total", "Total completed GC cycles.", "counter", float64(mem.NumGC))
}
