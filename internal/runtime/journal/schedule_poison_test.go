package journal

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A malformed old SQLite wake_at must not take the only scheduler batch slot
// or the tenant's only admission rank ahead of a valid due continuation.
func TestFindDueSchedulesMalformedWakeDoesNotStarveTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	seedDueSleeps(t, j, "poisoned", 3, time.Now().UTC().Add(-2*time.Hour))
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "poisoned", MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx,
		`UPDATE schedules SET wake_at = '146138514283-06-19T00:00:00.000Z' WHERE run_id = 'run_poisoned_0'`); err != nil {
		t.Fatal(err)
	}
	// SQLite accepts a date-only string as a Julian day, but Reactor's
	// parser does not. It must not occupy the next admission rank either.
	if _, err := j.db.ExecContext(ctx,
		`UPDATE schedules SET wake_at = '2020-01-01' WHERE run_id = 'run_poisoned_1'`); err != nil {
		t.Fatal(err)
	}

	due, err := j.FindDueSchedules(ctx, time.Now().UTC(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].RunID != "run_poisoned_2" {
		t.Fatalf("due schedules = %+v; malformed older row must not hide valid continuation", due)
	}
}

// SQLite TEXT ordering compares wall-clock strings, not instants. Two valid
// RFC3339 offset values can therefore both wake a run early and hide an
// already-due continuation from the same capped tenant.
func TestFindDueSchedulesOffsetWakeUsesInstant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	now := time.Date(2026, time.October, 4, 12, 0, 0, 0, time.UTC)
	seedDueSleeps(t, j, "offset", 2, now.Add(-3*time.Hour))
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "offset", MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	for runID, wake := range map[string]string{
		"run_offset_0": "2026-10-04T11:30:00-01:00", // 12:30 UTC: future
		"run_offset_1": "2026-10-04T13:00:00+02:00", // 11:00 UTC: due
	} {
		if _, err := j.db.ExecContext(ctx,
			`UPDATE schedules SET wake_at = ? WHERE run_id = ?`, wake, runID); err != nil {
			t.Fatal(err)
		}
	}

	due, err := j.FindDueSchedules(ctx, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].RunID != "run_offset_1" || !due[0].WakeAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("noon due schedules = %+v; wanted only the 11:00 UTC run", due)
	}
	if err := j.UpsertTenant(ctx, Tenant{TenantID: "offset", MaxConcurrentRuns: 0}); err != nil {
		t.Fatal(err)
	}
	due, err = j.FindDueSchedules(ctx, now.Add(31*time.Minute), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 || due[0].RunID != "run_offset_1" || due[1].RunID != "run_offset_0" {
		t.Fatalf("12:31 UTC due schedules = %+v; wanted instant order past then future", due)
	}
}

func TestFireSignalOffsetExpiryUsesInstant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const token = "sig_offset_future"
	if _, err := j.ScheduleSignalSeq(ctx, "run_1", "approval", 1, "approval", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// This is one hour in the future, but its -02:00 wall clock is one hour
	// behind UTC now. A lexical UPDATE predicate incorrectly rejects it.
	future := time.Now().UTC().Add(time.Hour).In(time.FixedZone("behind", -2*60*60))
	if _, err := j.db.ExecContext(ctx,
		`UPDATE schedules SET wake_at = ? WHERE run_id = 'run_1' AND kind = 'signal'`,
		future.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	runID, signalName, err := j.FireSignal(ctx, token, []byte(`"approved"`))
	if errors.Is(err, ErrAlreadyFired) {
		t.Fatalf("valid future offset deadline was treated as already fired: %v", err)
	}
	if err != nil || runID != "run_1" || signalName != "approval" {
		t.Fatalf("offset signal delivery = %q/%q, %v", runID, signalName, err)
	}
}
