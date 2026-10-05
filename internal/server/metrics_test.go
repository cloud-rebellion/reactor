package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeCapacityProbes(t *testing.T) {
	m := NewMetrics()
	m.QueueDepth = func(_ context.Context) (int, error) { return 7, nil }
	m.QueueClaimable = func(_ context.Context) (int, error) { return 3, nil }
	m.WorkerCapacity = func(_ context.Context, _ time.Duration) (int, int, error) { return 2, 16, nil }
	s := &Server{Metrics: m}
	rec := httptest.NewRecorder()
	s.metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"reactor_queue_depth 7",
		"reactor_queue_claimable_depth 3",
		"reactor_queue_claimable_probe_ok 1",
		"reactor_worker_count 2",
		"reactor_worker_capacity 16",
		"reactor_capacity_probe_ok 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, body)
		}
	}
}

func TestMetricsMarkCapacityProbeFailureWithoutClaimingZero(t *testing.T) {
	m := NewMetrics()
	m.QueueDepth = func(_ context.Context) (int, error) { return 0, errors.New("database unavailable") }
	m.QueueClaimable = func(_ context.Context) (int, error) { return 0, errors.New("database unavailable") }
	m.WorkerCapacity = func(_ context.Context, _ time.Duration) (int, int, error) {
		return 0, 0, errors.New("database unavailable")
	}
	s := &Server{Metrics: m}
	rec := httptest.NewRecorder()
	s.metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"reactor_queue_depth -1",
		"reactor_queue_claimable_depth -1",
		"reactor_queue_claimable_probe_ok 0",
		"reactor_worker_count -1",
		"reactor_worker_capacity -1",
		"reactor_capacity_probe_ok 0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing failure marker %q in:\n%s", want, body)
		}
	}
}

func TestMetricsExposeDatabasePoolPressure(t *testing.T) {
	m := NewMetrics()
	m.DBPoolStats = func() sql.DBStats {
		return sql.DBStats{
			MaxOpenConnections: 20, OpenConnections: 18, InUse: 17, Idle: 1,
			WaitCount: 7, WaitDuration: 2250 * time.Millisecond,
		}
	}
	s := &Server{Metrics: m}
	rec := httptest.NewRecorder()
	s.metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{
		"reactor_db_pool_max_open_connections 20",
		"reactor_db_pool_open_connections 18",
		"reactor_db_pool_in_use_connections 17",
		"reactor_db_pool_idle_connections 1",
		"reactor_db_pool_wait_total 7",
		"reactor_db_pool_wait_seconds_total 2.25",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("metrics missing %q", want)
		}
	}
}

func TestMetricsExposeQueueAgeAndDoNotHideProbeFailure(t *testing.T) {
	m := NewMetrics()
	m.QueueOldestAge = func(context.Context) (time.Duration, error) { return 45 * time.Second, nil }
	s := &Server{Metrics: m}
	scrape := func() string {
		rec := httptest.NewRecorder()
		s.metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	for _, want := range []string{"reactor_queue_oldest_age_seconds 45", "reactor_queue_age_probe_ok 1"} {
		if !strings.Contains(scrape(), want) {
			t.Fatalf("queue age metric missing %q", want)
		}
	}
	m.QueueOldestAge = func(context.Context) (time.Duration, error) { return 0, errors.New("database unavailable") }
	body := scrape()
	for _, want := range []string{"reactor_queue_oldest_age_seconds -1", "reactor_queue_age_probe_ok 0"} {
		if !strings.Contains(body, want) {
			t.Fatalf("failed queue age probe missing %q", want)
		}
	}
}
