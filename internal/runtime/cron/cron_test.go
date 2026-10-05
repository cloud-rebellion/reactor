package cron

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

type captureDispatcher struct {
	calls atomic.Int32
	last  []byte
	trig  journal.Trigger
}

func (c *captureDispatcher) Dispatch(_ context.Context, t journal.Trigger, payload []byte) error {
	c.calls.Add(1)
	c.last = append([]byte(nil), payload...)
	c.trig = t
	return nil
}

func newTestDriver(t *testing.T, spec string) (*Driver, *captureDispatcher, *journal.Journal) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cron.db")
	url := "sqlite://" + dbPath

	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	j := journal.New(db, journal.EngineSQLite)

	if err := j.CreateWorkflow(context.Background(), "wf_1", "demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	cfg, _ := json.Marshal(Config{Spec: spec, Timezone: "UTC"})
	if _, err := j.CreateCronTrigger(context.Background(), "wf_1", cfg); err != nil {
		t.Fatalf("create cron: %v", err)
	}

	disp := &captureDispatcher{}
	d := &Driver{Journal: j, Disp: disp, Log: silent}
	return d, disp, j
}

// TestCronFiresOnSchedule starts the driver with a "every minute" spec and
// instead of waiting 60 seconds, exercises the dispatch path by triggering
// a fire manually via the unexported fire() method (test-friendly bypass).
// A real-clock test would need to wait for the cron tick which is too slow;
// what we want to validate here is the wiring (load -> dispatch -> mark fired).
func TestCronStartLoadsTriggers(t *testing.T) {
	t.Parallel()
	d, disp, j := newTestDriver(t, "* * * * *")

	if err := d.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer d.Stop()

	if len(d.loaded) != 1 {
		t.Fatalf("loaded %d, want 1", len(d.loaded))
	}

	// Drive a fire directly to exercise dispatch + journal updates.
	d.fire(context.Background(), d.loaded[0])
	if disp.calls.Load() != 1 {
		t.Fatalf("dispatch %d, want 1", disp.calls.Load())
	}
	got, err := j.FindWebhookByToken(context.Background(), "n/a") // wrong helper; use ListCronTriggers
	_ = got
	_ = err
	cron, err := j.ListCronTriggers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cron[0].LastFiredAt == nil {
		t.Fatal("last_fired_at not set")
	}
}

func TestCronRejectsBadSpec(t *testing.T) {
	t.Parallel()
	d, _, _ := newTestDriver(t, "this is not cron")
	if err := d.Start(context.Background()); err == nil {
		t.Fatal("bad spec should fail Start")
	}
}

func TestCronRejectsEmptySpec(t *testing.T) {
	t.Parallel()
	d, _, _ := newTestDriver(t, "")
	if err := d.Start(context.Background()); err == nil {
		t.Fatal("empty spec should fail Start")
	}
}

func TestCronStartTwiceErrors(t *testing.T) {
	t.Parallel()
	d, _, _ := newTestDriver(t, "* * * * *")
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	if err := d.Start(context.Background()); err == nil {
		t.Fatal("double Start should error")
	}
}

// TestCronRealTickFires exercises the actual cron clock with a near-future
// schedule. We use "@every 200ms" so the test runs in <500ms total.
func TestCronRealTickFires(t *testing.T) {
	t.Parallel()
	d, disp, _ := newTestDriver(t, "@every 200ms")
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if disp.calls.Load() >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("cron never fired in 2s")
}

// TestCronReconcileAdds picks up a cron trigger inserted after Start.
func TestCronReconcileAdds(t *testing.T) {
	t.Parallel()
	d, _, j := newTestDriver(t, "* * * * *")
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	if len(d.loaded) != 1 {
		t.Fatalf("loaded %d, want 1", len(d.loaded))
	}

	// Add a second cron trigger and reconcile.
	if err := j.CreateWorkflow(context.Background(), "wf_2", "two", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(Config{Spec: "*/5 * * * *"})
	if _, err := j.CreateCronTrigger(context.Background(), "wf_2", cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.loaded) != 2 {
		t.Fatalf("after reconcile loaded %d, want 2", len(d.loaded))
	}
	if len(d.entries) != 2 {
		t.Fatalf("after reconcile entries %d, want 2", len(d.entries))
	}
}

// TestCronReconcileRemovesDeactivated drops a trigger and reconciles.
func TestCronReconcileRemovesDeactivated(t *testing.T) {
	t.Parallel()
	d, _, j := newTestDriver(t, "* * * * *")
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	id := d.loaded[0].ID

	if err := j.SetTriggerState(context.Background(), id, "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := d.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.entries) != 0 {
		t.Fatalf("after deactivate entries %d, want 0", len(d.entries))
	}
}

// A clock callback may already be queued when an operator disables a
// trigger. The callback must re-read the durable state instead of dispatching
// the stale row captured by robfig/cron.
func TestCronFireRechecksAuthoritativeTriggerState(t *testing.T) {
	t.Parallel()
	d, disp, j := newTestDriver(t, "* * * * *")
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	captured := d.loaded[0]
	if err := j.SetTriggerState(context.Background(), captured.ID, "disabled"); err != nil {
		t.Fatalf("disable trigger: %v", err)
	}
	d.fire(context.Background(), captured)
	if got := disp.calls.Load(); got != 0 {
		t.Fatalf("stale cron callback dispatched %d run(s), want 0", got)
	}
}

// TestCronReloadLoopFiresReconcile asserts the periodic loop picks up a
// new trigger without an explicit Reconcile call.
func TestCronReloadLoopFiresReconcile(t *testing.T) {
	t.Parallel()
	d, _, j := newTestDriver(t, "* * * * *")
	d.ReloadInterval = 50 * time.Millisecond
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()

	if err := j.CreateWorkflow(context.Background(), "wf_3", "three", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(Config{Spec: "*/10 * * * *"})
	if _, err := j.CreateCronTrigger(context.Background(), "wf_3", cfg); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		n := len(d.entries)
		d.mu.Unlock()
		if n == 2 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("reload loop never picked up the new trigger")
}
