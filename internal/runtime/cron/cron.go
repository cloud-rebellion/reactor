// Package cron is the cron-trigger driver. Loads cron-kind triggers at
// startup, registers them with robfig/cron/v3, and on each fire dispatches
// a run via the configured Dispatcher (the same interface webhooks use).
//
// Spec format: 6-field robfig spec (with seconds) for high precision, or
// 5-field standard cron with the `cron.SecondParser` disabled. v0 uses
// 5-field standard cron because most users think in minutes; precision can
// be opt-in later via a config flag.
//
// Live-reload: when ReloadInterval > 0, Start() spawns a reconcile loop
// that polls the triggers table on each tick and adds/removes entries to
// match the current state. Operators editing triggers via SQL or the
// CLI no longer need a daemon restart.
package cron

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	robfig "github.com/robfig/cron/v3"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Dispatcher mirrors the webhook package's contract; cron and webhook share
// one shape so the supervisor can be wired through one Run lookup.
type Dispatcher interface {
	Dispatch(ctx context.Context, t journal.Trigger, payload []byte) error
}

// Config carries the cron expression and timezone.
type Config struct {
	Spec     string `json:"spec"`
	Timezone string `json:"timezone,omitempty"`
}

// Driver runs cron-kind triggers.
type Driver struct {
	Journal *journal.Journal
	Disp    Dispatcher
	Log     *slog.Logger

	// ReloadInterval, when > 0, drives a periodic reconcile against the
	// triggers table so operators can add/remove cron entries without
	// restarting the daemon. Zero (default) keeps the legacy startup-
	// only behaviour.
	ReloadInterval time.Duration

	// Listener, when non-nil, runs a Postgres LISTEN/NOTIFY subscriber
	// alongside the polling reconcile so trigger CRUD takes effect
	// within milliseconds. Polling stays as the dropped-notification
	// safety net. SQLite deployments leave this nil.
	Listener PgListenerIface

	mu      sync.Mutex
	cron    *robfig.Cron
	loaded  []journal.Trigger
	started bool

	// entries maps trigger ID -> robfig EntryID + the spec we registered
	// with. Reconcile compares against this to detect adds, removes, and
	// spec changes.
	entries map[string]entryRecord

	stopReload chan struct{}
	reloadDone chan struct{}
}

type entryRecord struct {
	id   robfig.EntryID
	spec string // includes timezone prefix when applicable
}

// PgListenerIface is the minimal LISTEN/NOTIFY surface the cron driver
// uses. *PgListener satisfies it; tests can pass a fake that fires
// onNotify on demand without touching real Postgres.
type PgListenerIface interface {
	Listen(ctx context.Context, onNotify func(payload string)) error
}

// Start loads all active cron triggers and begins the cron clock. Returns
// an error if any spec is malformed; the driver refuses partial startup so
// a typo in one trigger doesn't silently disable it.
func (d *Driver) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return errors.New("cron: already started")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	// UTC is the right default: robfig defaults to time.Local, which
	// would mean the same trigger fires at different wall-clock times
	// across deployments and shifts on DST transitions. Operators who
	// want a wall-clock cadence still set the per-trigger Timezone
	// (lives in Config.Timezone -> CRON_TZ prefix in buildSpec).
	d.cron = robfig.New(robfig.WithLocation(time.UTC)) // 5-field standard cron, UTC default
	d.entries = map[string]entryRecord{}
	d.mu.Unlock()

	if err := d.reconcileLocked(ctx); err != nil {
		return err
	}

	d.mu.Lock()
	d.cron.Start()
	d.started = true
	loadedCount := len(d.loaded)
	d.mu.Unlock()
	d.Log.Info("cron driver started", "triggers", loadedCount)

	if d.ReloadInterval > 0 {
		d.mu.Lock()
		d.stopReload = make(chan struct{})
		d.reloadDone = make(chan struct{})
		// Snapshot the channels under the lock so the goroutine doesn't
		// race with Stop() nilling them out at shutdown.
		stop, done, interval := d.stopReload, d.reloadDone, d.ReloadInterval
		d.mu.Unlock()
		go d.reloadLoop(ctx, stop, done, interval)
	}
	// Postgres LISTEN/NOTIFY path: when a PgListener is wired, run it
	// alongside the polling reloadLoop. The polling loop becomes the
	// safety net for dropped notifications; LISTEN is the fast path.
	if d.Listener != nil {
		go func() {
			if err := d.Listener.Listen(ctx, func(payload string) {
				d.Log.Debug("cron: trigger change notify", "payload", payload)
				if err := d.Reconcile(ctx); err != nil {
					d.Log.Warn("cron: reconcile after notify failed", "err", err)
				}
			}); err != nil && ctx.Err() == nil {
				d.Log.Warn("cron: pg listener exited", "err", err)
			}
		}()
	}
	return nil
}

// Stop halts the cron loop and waits for in-flight jobs to finish.
func (d *Driver) Stop() {
	d.mu.Lock()
	stopReload := d.stopReload
	reloadDone := d.reloadDone
	d.stopReload = nil
	d.reloadDone = nil
	d.mu.Unlock()
	if stopReload != nil {
		close(stopReload)
		<-reloadDone
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cron != nil {
		stopCtx := d.cron.Stop()
		<-stopCtx.Done()
		d.cron = nil
	}
	d.entries = nil
	d.started = false
}

// Reconcile re-reads the active cron triggers and applies the diff to
// the running cron schedule. Exposed for tests + the daemon's optional
// SIGHUP-style hooks.
func (d *Driver) Reconcile(ctx context.Context) error {
	return d.reconcileLocked(ctx)
}

// reconcileLocked acquires d.mu, diffs the loaded triggers against the
// current entries map, and adds/removes entries to match. On the very
// first call (Start), every trigger is "new" and gets added; subsequent
// calls compare specs to detect edits.
func (d *Driver) reconcileLocked(ctx context.Context) error {
	triggers, err := d.findActiveCronTriggers(ctx)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cron == nil {
		return errors.New("cron: not started")
	}

	desired := map[string]journal.Trigger{}
	for _, t := range triggers {
		desired[t.ID] = t
	}

	// Remove entries for triggers that disappeared or whose spec changed.
	for id, rec := range d.entries {
		t, ok := desired[id]
		if !ok {
			d.cron.Remove(rec.id)
			delete(d.entries, id)
			d.Log.Info("cron: removed trigger", "trigger_id", id)
			continue
		}
		spec, err := buildSpec(t)
		if err != nil {
			// A malformed spec on a previously-loaded trigger: drop the
			// entry + log so the bad row doesn't keep firing the old one.
			d.cron.Remove(rec.id)
			delete(d.entries, id)
			d.Log.Error("cron: dropping trigger with bad spec", "trigger_id", id, "err", err)
			_ = d.Journal.MarkTriggerError(ctx, id, "cron reconcile: "+err.Error())
			continue
		}
		if spec != rec.spec {
			d.cron.Remove(rec.id)
			delete(d.entries, id)
			d.Log.Info("cron: spec changed, re-registering", "trigger_id", id, "old", rec.spec, "new", spec)
		}
	}

	// Add entries for new (or just-removed-due-to-spec-change) triggers.
	for id, t := range desired {
		if _, ok := d.entries[id]; ok {
			continue
		}
		spec, err := buildSpec(t)
		if err != nil {
			// On Start (no entries yet), refuse partial startup so a typo
			// fails fast. On a later reconcile (entries non-nil and we
			// already removed bad ones above), log + skip so other
			// triggers keep running.
			if !d.started {
				return fmt.Errorf("cron: trigger %s: %w", id, err)
			}
			d.Log.Error("cron: skipping bad trigger", "trigger_id", id, "err", err)
			_ = d.Journal.MarkTriggerError(ctx, id, "cron reconcile: "+err.Error())
			continue
		}
		trig := t // capture
		entryID, err := d.cron.AddFunc(spec, func() { d.fire(ctx, trig) })
		if err != nil {
			if !d.started {
				return fmt.Errorf("cron: add %s: %w", id, err)
			}
			d.Log.Error("cron: AddFunc failed", "trigger_id", id, "err", err)
			_ = d.Journal.MarkTriggerError(ctx, id, "cron reconcile: "+err.Error())
			continue
		}
		d.entries[id] = entryRecord{id: entryID, spec: spec}
		if d.started {
			d.Log.Info("cron: registered new trigger", "trigger_id", id, "spec", spec)
		}
	}

	d.loaded = triggers
	return nil
}

// reloadLoop ticks every interval and reconciles. Exits cleanly on stop
// close. Channels + interval are captured at goroutine start so Stop()
// can safely nil out the struct fields without racing the read paths.
func (d *Driver) reloadLoop(ctx context.Context, stop, done chan struct{}, interval time.Duration) {
	defer close(done)
	defer func() {
		if r := recover(); r != nil {
			d.Log.Error("cron: reloadLoop panicked",
				"panic", r, "stack", string(debug.Stack()))
		}
	}()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.Reconcile(ctx); err != nil {
				d.Log.Warn("cron: reconcile failed", "err", err)
			}
		}
	}
}

// buildSpec encodes a trigger's spec + timezone in robfig's CRON_TZ form.
func buildSpec(t journal.Trigger) (string, error) {
	var cfg Config
	if len(t.Config) > 0 {
		if err := json.Unmarshal(t.Config, &cfg); err != nil {
			return "", fmt.Errorf("config: %w", err)
		}
	}
	if cfg.Spec == "" {
		return "", errors.New("empty spec")
	}
	if cfg.Timezone != "" {
		return "CRON_TZ=" + cfg.Timezone + " " + cfg.Spec, nil
	}
	return cfg.Spec, nil
}

// fire dispatches one cron run. Errors are logged + stamped on the trigger
// row; one bad fire never kills the cron loop.
func (d *Driver) fire(ctx context.Context, t journal.Trigger) {
	// The cron callback captures a trigger snapshot when its entry is
	// registered. A disable, tenant repair, or other authoring mutation can
	// race the reload loop, so never dispatch that stale snapshot. Resolve the
	// active row at the dispatch boundary; a missing/disabled row is an expected
	// no-op while a database failure is logged and left for the next tick.
	fresh, err := d.Journal.GetActiveCronTrigger(ctx, t.ID)
	if err != nil {
		if !errors.Is(err, journal.ErrNotFound) {
			d.Log.Warn("cron: resolve trigger before dispatch failed", "trigger_id", t.ID, "err", err)
		}
		return
	}
	t = fresh
	payload, _ := json.Marshal(map[string]any{
		"trigger_id": t.ID,
		"fired_at":   time.Now().UTC().Format(time.RFC3339),
	})
	if err := d.Disp.Dispatch(ctx, t, payload); err != nil {
		d.Log.Error("cron: dispatch failed", "trigger_id", t.ID, "err", err)
		_ = d.Journal.MarkTriggerError(ctx, t.ID, "cron dispatch: "+err.Error())
		return
	}
	if err := d.Journal.MarkTriggerFired(ctx, t.ID); err != nil {
		d.Log.Warn("cron: mark fired", "trigger_id", t.ID, "err", err)
	}
}

// findActiveCronTriggers reads the cron-kind triggers. Lives in this
// package so the journal interface stays small; this is the only place
// that needs an arbitrary `WHERE kind = 'cron' AND state = 'active'`.
func (d *Driver) findActiveCronTriggers(ctx context.Context) ([]journal.Trigger, error) {
	return d.Journal.ListCronTriggers(ctx)
}
