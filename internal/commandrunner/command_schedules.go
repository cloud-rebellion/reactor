package commandrunner

// This file is the unattended cron path for command plans. It is deliberately
// separate from internal/runtime/cron: workflow triggers have workflow-only
// dispatch semantics and their table cannot safely point at command plans.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	robfig "github.com/robfig/cron/v3"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// CommandScheduleDriver owns one leader's in-process view of active command
// schedules. The schedule and its immutable receipt are loaded from the
// tenant-fenced journal on every reconcile; command text and credentials never
// enter this package's trigger payload.
type CommandScheduleDriver struct {
	Journal        *journal.Journal
	Runner         *Runner
	Queue          *Queue
	TenantID       string
	Log            *slog.Logger
	ReloadInterval time.Duration
	// Now is captured at callback entry to derive the deterministic schedule
	// slot. Keeping the clock injectable also lets the runtime test the
	// at-most-once event identity without waiting for a wall-clock minute.
	// A nil clock uses time.Now.
	Now func() time.Time

	mu      sync.Mutex
	cron    *robfig.Cron
	entries map[string]commandScheduleEntry
	started bool
	stop    chan struct{}
	done    chan struct{}
	fireSem chan struct{}
}

// Start refuses malformed active schedules before starting the clock. A
// disabled or missing schedule is simply absent from the desired set and can
// be enabled later through the MCP CAS mutation followed by reconcile.
func (d *CommandScheduleDriver) Start(ctx context.Context) error {
	if d == nil || d.Journal == nil || d.Runner == nil || d.Queue == nil {
		return errors.New("command schedules: journal, runner, and queue are required")
	}
	if strings.TrimSpace(d.TenantID) == "" {
		return errors.New("command schedules: tenant is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return errors.New("command schedules: already started")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	d.cron = robfig.New(robfig.WithLocation(time.UTC))
	d.entries = make(map[string]commandScheduleEntry)
	d.fireSem = make(chan struct{}, 16)
	d.mu.Unlock()
	if err := d.reconcile(ctx); err != nil {
		d.mu.Lock()
		d.cron = nil
		d.entries = nil
		d.mu.Unlock()
		return err
	}
	d.mu.Lock()
	d.cron.Start()
	d.started = true
	if d.ReloadInterval > 0 {
		d.stop = make(chan struct{})
		d.done = make(chan struct{})
		stop, done, interval := d.stop, d.done, d.ReloadInterval
		go d.reloadLoop(ctx, stop, done, interval)
	}
	loaded := len(d.entries)
	d.mu.Unlock()
	d.Log.Info("command schedule driver started", "tenant_id", d.TenantID, "schedules", loaded)
	return nil
}

// Stop removes the clock and waits for a reconcile loop. Cron jobs already in
// flight are allowed to finish their bounded admission/queue handoff.
func (d *CommandScheduleDriver) Stop() {
	if d == nil {
		return
	}
	d.mu.Lock()
	stop, done, cron := d.stop, d.done, d.cron
	d.stop, d.done = nil, nil
	// Do not hold d.mu while waiting for cron.Stop below. A cron callback
	// takes this mutex to read fireSem; holding it while cron.Stop waits for
	// callbacks would deadlock shutdown if a callback is already starting.
	d.fireSem = nil
	d.entries = nil
	d.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	if cron != nil {
		stopCtx := cron.Stop()
		<-stopCtx.Done()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// Start is rejected until the old clock has fully stopped. This also
	// keeps a concurrent Reconcile from observing a half-stopped cron.
	d.cron = nil
	d.started = false
}

// Reconcile applies schedule CRUD without requiring a daemon restart.
func (d *CommandScheduleDriver) Reconcile(ctx context.Context) error {
	if d == nil {
		return errors.New("command schedules: nil driver")
	}
	return d.reconcile(ctx)
}

func (d *CommandScheduleDriver) reconcile(ctx context.Context) error {
	schedules, err := d.activeSchedules(ctx)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cron == nil {
		return errors.New("command schedules: not started")
	}
	desired := make(map[string]journal.CommandAutomationSchedule, len(schedules))
	for _, schedule := range schedules {
		desired[schedule.ID] = schedule
	}
	for id, entry := range d.entries {
		if _, ok := desired[id]; !ok {
			d.cron.Remove(entry.id)
			delete(d.entries, id)
		}
	}
	for id, schedule := range desired {
		spec, err := commandScheduleSpec(schedule)
		if err != nil {
			// If an imported or legacy row becomes malformed after an entry was
			// installed, remove the old cron job too. Continuing to fire the last
			// valid expression would silently execute a schedule the durable row no
			// longer authorizes.
			if current, ok := d.entries[id]; ok {
				d.cron.Remove(current.id)
				delete(d.entries, id)
			}
			_ = d.Journal.MarkCommandAutomationScheduleError(ctx, d.TenantID, id, "schedule rejected: "+err.Error())
			if !d.started {
				return fmt.Errorf("command schedules: %s: %w", id, err)
			}
			continue
		}
		if current, ok := d.entries[id]; ok {
			if current.spec == spec {
				continue
			}
			// The schedule row may have been disabled, edited, and re-enabled
			// between reload polls. Keep the cron clock aligned with the
			// authoritative compiled expression instead of retaining the old
			// timing solely because the opaque trigger id is unchanged.
			d.cron.Remove(current.id)
			delete(d.entries, id)
		}
		captured := schedule
		entry, err := d.cron.AddFunc(spec, func() { d.fire(captured) })
		if err != nil {
			if !d.started {
				return fmt.Errorf("command schedules: add %s: %w", id, err)
			}
			_ = d.Journal.MarkCommandAutomationScheduleError(ctx, d.TenantID, id, "schedule rejected: "+err.Error())
			continue
		}
		d.entries[id] = commandScheduleEntry{id: entry, spec: spec}
	}
	return nil
}

type commandScheduleEntry struct {
	id   robfig.EntryID
	spec string
}

func (d *CommandScheduleDriver) reloadLoop(ctx context.Context, stop, done chan struct{}, interval time.Duration) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.reconcile(ctx); err != nil && d.Log != nil {
				d.Log.Warn("command schedules: reconcile failed", "err", err)
			}
		}
	}
}

func (d *CommandScheduleDriver) activeSchedules(ctx context.Context) ([]journal.CommandAutomationSchedule, error) {
	const pageSize = 500
	var out []journal.CommandAutomationSchedule
	for offset := 0; ; offset += pageSize {
		rows, more, err := d.Journal.ListCommandAutomationSchedulesForTenantPage(ctx, journal.CommandAutomationScheduleFilter{
			TenantID: d.TenantID, State: journal.CommandAutomationScheduleActive, Limit: pageSize, Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if !more || len(rows) == 0 {
			return out, nil
		}
	}
}

func commandScheduleSpec(schedule journal.CommandAutomationSchedule) (string, error) {
	spec := strings.TrimSpace(schedule.Spec)
	if spec == "" {
		return "", errors.New("empty cron spec")
	}
	if len(strings.Fields(spec)) != 5 {
		return "", errors.New("cron spec must contain exactly five fields")
	}
	if schedule.Timezone != "" {
		if _, err := time.LoadLocation(schedule.Timezone); err != nil {
			return "", fmt.Errorf("invalid timezone: %w", err)
		}
		spec = "CRON_TZ=" + schedule.Timezone + " " + spec
	}
	// Event identity is derived from a standard cron minute slot. Reject
	// robfig descriptors such as @every 10s here instead of silently
	// collapsing multiple firings into one minute-scoped receipt. MCP creation
	// uses the same ParseStandard contract; this runtime check protects
	// imported/legacy rows and keeps direct journal writes fail closed.
	if _, err := robfig.ParseStandard(spec); err != nil {
		return "", fmt.Errorf("invalid cron spec: %w", err)
	}
	return spec, nil
}

func (d *CommandScheduleDriver) fire(schedule journal.CommandAutomationSchedule) {
	// Capture the slot before waiting on the admission semaphore or reading the
	// journal. A slow database/runner handoff can cross a minute boundary; if
	// the event id were derived later, one cron tick could be admitted under a
	// different id and then run again on the next tick.
	slot := d.now().UTC().Truncate(time.Minute)
	d.mu.Lock()
	sem := d.fireSem
	d.mu.Unlock()
	if sem == nil {
		return
	}
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		if d.Log != nil {
			d.Log.Warn("command schedules: admission concurrency limit reached", "schedule_id", schedule.ID)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Cron entries are intentionally stable across reconciles, so the row
	// captured when an entry was installed may have an older revision after a
	// prior fire (MarkCommandAutomationScheduleFired advances it). Re-read the
	// authoritative active row on every tick. This also closes a race where a
	// schedule is disabled between cron dispatch and this callback.
	fresh, err := d.Journal.GetCommandAutomationScheduleForTenant(ctx, d.TenantID, schedule.ID)
	if err != nil {
		if d.Log != nil {
			d.Log.Warn("command schedules: resolve schedule before fire failed", "schedule_id", schedule.ID, "err", err)
		}
		return
	}
	if fresh.State != journal.CommandAutomationScheduleActive {
		return
	}
	schedule = fresh
	// Standard five-field cron has minute precision. The slot captured at
	// callback entry gives a stable event id across slow admission and leader
	// retries within that slot.
	eventID := journal.CommandAutomationScheduleEventID(schedule.ID, slot)
	req := Request{TenantID: schedule.TenantID, AutomationID: schedule.AutomationID, Version: schedule.AutomationVersion, TriggerID: schedule.ID, TriggerEventID: eventID}
	result, err := d.Runner.AdmitScheduled(ctx, req, schedule)
	if err != nil {
		if d.Log != nil {
			d.Log.Warn("command schedules: admission failed", "schedule_id", schedule.ID, "err", err)
		}
		_ = d.Journal.MarkCommandAutomationScheduleError(ctx, d.TenantID, schedule.ID, "admission failed: "+err.Error())
		return
	}
	queueReq := req
	queueReq.RunID = result.Run.ID
	queueReq.Admission = result.Run.Admission
	// A retry of the same schedule slot can resolve to an existing queued,
	// running, or terminal run. Only a newly-created or still-queued row needs
	// another in-memory handoff; re-enqueuing a terminal receipt just creates a
	// noisy rejected job and cannot make execution more reliable.
	if result.Run.Created || result.Run.Status == journal.CommandRunQueued {
		if err := d.Queue.Enqueue(ctx, queueReq); err != nil && !errors.Is(err, ErrQueueFull) {
			if d.Log != nil {
				d.Log.Warn("command schedules: queue handoff failed", "schedule_id", schedule.ID, "run_id", result.Run.ID, "err", err)
			}
			_ = d.Journal.MarkCommandAutomationScheduleError(ctx, d.TenantID, schedule.ID, "queue handoff failed: "+err.Error())
			return
		}
	}
	if err := markScheduleFiredWithRetry(ctx, d.Journal, d.TenantID, schedule.ID); err != nil && d.Log != nil {
		d.Log.Warn("command schedules: mark fired failed", "schedule_id", schedule.ID, "err", err)
	}
}

func (d *CommandScheduleDriver) now() time.Time {
	if d != nil && d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// markScheduleFiredWithRetry closes a small SQLite writer-lock race between
// command admission/queue recovery and the trigger acknowledgement. SQLite's
// busy timeout is configured for production handles, but embedded callers and
// tests can supply an already-open *sql.DB without that pragma. A failed
// acknowledgement is otherwise observable as a healthy command run with a
// stale schedule receipt; retrying only the known SQLITE_BUSY forms preserves
// fail-closed behavior for every other database error.
func markScheduleFiredWithRetry(ctx context.Context, j *journal.Journal, tenantID, scheduleID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	const maxAttempts = 5
	delay := 10 * time.Millisecond
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = j.MarkCommandAutomationScheduleFired(ctx, tenantID, scheduleID)
		if err == nil || !isSQLiteBusyError(err) || attempt == maxAttempts-1 {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		if delay < 200*time.Millisecond {
			delay *= 2
		}
	}
	return err
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "sqlite_busy")
}
