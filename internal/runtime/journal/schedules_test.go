package journal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestScheduleSleepAndFindDue(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	now := time.Now().UTC()
	pastA, _ := j.ScheduleSleep(ctx, "run_1", "wait-a", now.Add(-time.Hour))
	pastB, _ := j.ScheduleSleep(ctx, "run_1", "wait-b", now.Add(-30*time.Minute))
	_, _ = j.ScheduleSleep(ctx, "run_1", "future", now.Add(time.Hour))
	if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}

	due, err := j.FindDueSchedules(ctx, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("got %d due, want 2", len(due))
	}
	if due[0].ID != pastA || due[1].ID != pastB {
		t.Fatalf("ordering wrong: %+v", due)
	}
}

// TestClaimScheduleIsCompareAndSet proves the resume claim is atomic: the
// first caller wins, a second caller (a peer daemon or a racing tick) gets
// claimed=false and must skip, so a suspended RunID is never double-run.
func TestClaimScheduleIsCompareAndSet(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	now := time.Now().UTC()
	id, _ := j.ScheduleSleep(ctx, "run_1", "wait", now.Add(-time.Minute))

	claimed, err := j.ClaimSchedule(ctx, id)
	if err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v, want true/nil", claimed, err)
	}
	claimed2, err := j.ClaimSchedule(ctx, id)
	if err != nil {
		t.Fatalf("second claim err: %v", err)
	}
	if claimed2 {
		t.Fatal("second claim returned true; CAS must reject an already-fired schedule")
	}
	// Unknown id also returns false, not an error.
	if claimed3, err := j.ClaimSchedule(ctx, "nope"); err != nil || claimed3 {
		t.Fatalf("missing-id claim: claimed=%v err=%v, want false/nil", claimed3, err)
	}
}

func TestFireScheduleHidesFromDue(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	now := time.Now().UTC()
	id, _ := j.ScheduleSleep(ctx, "run_1", "wait", now.Add(-time.Minute))

	if err := j.FireSchedule(ctx, id); err != nil {
		t.Fatal(err)
	}
	due, _ := j.FindDueSchedules(ctx, now, 10)
	if len(due) != 0 {
		t.Fatalf("fired schedule still due: %+v", due)
	}
}

func TestFireScheduleMissing(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if err := j.FireSchedule(context.Background(), "nope"); err == nil {
		t.Fatal("want error on missing id")
	}
}

func TestFindLatestSleepSchedule(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	now := time.Now().UTC()
	_, _ = j.ScheduleSleep(ctx, "run_1", "wait", now.Add(time.Hour))
	time.Sleep(2 * time.Millisecond) // ensure ordering by created_at
	id2, _ := j.ScheduleSleep(ctx, "run_1", "wait", now.Add(2*time.Hour))

	got, err := j.FindLatestSleepSchedule(ctx, "run_1", "wait")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id2 {
		t.Fatalf("got %s, want %s", got.ID, id2)
	}
}

func TestFindLatestSleepNotFound(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if _, err := j.FindLatestSleepSchedule(context.Background(), "run_1", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestScheduleSignalAndFire(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	expires := time.Now().UTC().Add(time.Hour)
	id, err := j.ScheduleSignal(ctx, "run_1", "wait-approval", "approval", "sig_token_aaa", expires)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("empty schedule id")
	}

	got, err := j.FindLatestSignalSchedule(ctx, "run_1", "wait-approval")
	if err != nil {
		t.Fatal(err)
	}
	if got.SignalToken != "sig_token_aaa" || got.SignalName != "approval" || got.Kind != "signal" {
		t.Fatalf("schedule shape wrong: %+v", got)
	}

	runID, name, err := j.FireSignal(ctx, "sig_token_aaa", []byte(`{"approved":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if runID != "run_1" || name != "approval" {
		t.Fatalf("got runID=%q name=%q, want run_1 / approval", runID, name)
	}

	// Second fire is rejected as already-delivered.
	if _, _, err := j.FireSignal(ctx, "sig_token_aaa", []byte(`{}`)); !errors.Is(err, ErrAlreadyFired) {
		t.Fatalf("second fire got %v, want ErrAlreadyFired", err)
	}

	// After delivery, FindLatestSignalSchedule sees the payload.
	post, err := j.FindLatestSignalSchedule(ctx, "run_1", "wait-approval")
	if err != nil {
		t.Fatal(err)
	}
	if string(post.SignalPayload) != `{"approved":true}` {
		t.Fatalf("payload = %q, want {\"approved\":true}", post.SignalPayload)
	}
}

func TestFireSignalUnknownToken(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if _, _, err := j.FireSignal(context.Background(), "sig_unknown", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestFindDueSchedulesIncludesSignalRows(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// Past-expiry signal row + a delivered signal row should both be due.
	now := time.Now().UTC()
	_, _ = j.ScheduleSignal(ctx, "run_1", "step-a", "approval", "sig_a", now.Add(-time.Minute))
	_, _ = j.ScheduleSignal(ctx, "run_1", "step-b", "approval", "sig_b", now.Add(time.Hour))

	if _, _, err := j.FireSignal(ctx, "sig_b", []byte(`"yes"`)); err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}

	// FireSignal bumps wake_at to time.Now() (which may be after the
	// captured `now`); query a moment in the future to capture both rows.
	due, err := j.FindDueSchedules(ctx, time.Now().UTC().Add(time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("got %d due, want 2: %+v", len(due), due)
	}
}

func TestSetRunStatus(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if err := j.SetRunStatus(context.Background(), "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(context.Background(), "missing", "running"); err == nil {
		t.Fatal("want error for missing run")
	}
}

// TestScheduleSeqSeparatesRepeatedAwaits pins the fix for a gate that
// auto-confirmed itself. Two AwaitSignal calls sharing a signal name used to
// de-duplicate on (run_id, step_name, kind) and collapse onto ONE row, so the
// second await was served the first's already-delivered payload and never
// suspended: one approval click satisfied an approve-then-confirm sequence.
func TestScheduleSeqSeparatesRepeatedAwaits(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	// Both awaits share the signal name, so they share the name-derived token.
	const tok = "sig_shared"
	if _, err := j.ScheduleSignalSeq(ctx, "run_1", "approval", 1, "approval", tok, exp); err != nil {
		t.Fatalf("first await: %v", err)
	}
	if _, err := j.ScheduleSignalSeq(ctx, "run_1", "approval", 2, "approval", tok, exp); err != nil {
		t.Fatalf("second await must get its own row (widened unique index): %v", err)
	}

	first, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal)
	if err != nil {
		t.Fatal(err)
	}
	second, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("the two awaits resolved to the same row; the ordinal is what keeps them apart")
	}

	// A delivery fills the OLDEST pending await, not an arbitrary one.
	if _, _, err := j.FireSignal(ctx, tok, []byte(`"yes"`)); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	got1, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal)
	if err != nil {
		t.Fatal(err)
	}
	if len(got1.SignalPayload) == 0 {
		t.Fatal("first await should have received the delivery")
	}
	got2, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal)
	if err != nil {
		t.Fatal(err)
	}
	if len(got2.SignalPayload) != 0 {
		t.Fatal("second await must still be pending after ONE delivery, or the gate auto-confirms")
	}

	// A second delivery to the same token fills the second await rather than
	// reporting ErrAlreadyFired forever and stranding it.
	if _, _, err := j.FireSignal(ctx, tok, []byte(`"confirmed"`)); err != nil {
		t.Fatalf("second delivery should reach the pending await: %v", err)
	}
	got2, err = j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal)
	if err != nil {
		t.Fatal(err)
	}
	if string(got2.SignalPayload) != `"confirmed"` {
		t.Fatalf("second await payload = %s, want \"confirmed\"", got2.SignalPayload)
	}
	// Now everything is delivered, so a third delivery is genuinely a replay.
	if _, _, err := j.FireSignal(ctx, tok, []byte(`"extra"`)); !errors.Is(err, ErrAlreadyFired) {
		t.Fatalf("third delivery = %v, want ErrAlreadyFired", err)
	}
}

// TestScheduleSeqSeparatesLoopSleeps is the Sleep half: a Sleep inside a loop
// matched the first iteration's row on every later iteration, and that row's
// wake_at was already past, so the host acked instantly and a per-item delay
// collapsed into a single sleep.
func TestScheduleSeqSeparatesLoopSleeps(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	if _, err := j.ScheduleSleepSeq(ctx, "run_1", "throttle", 1, past); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSleepSeq(ctx, "run_1", "throttle", 2, future); err != nil {
		t.Fatal(err)
	}

	second, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSleep)
	if err != nil {
		t.Fatal(err)
	}
	if !second.WakeAt.After(time.Now()) {
		t.Fatal("iteration 2 resolved to iteration 1's already-past wake_at, so it would ack instantly")
	}
	// seq 0 is the pre-ordinal marker and must not resolve.
	if _, err := j.FindScheduleBySeq(ctx, "run_1", 0, KindSleep); !errors.Is(err, ErrNotFound) {
		t.Fatalf("seq 0 = %v, want ErrNotFound", err)
	}
}

// TestFindDueSchedulesSkipsUnparseableWakeAt guards an estate-wide wedge.
// wake_at is TEXT, so an out-of-range timestamp (a workflow-controlled
// Sleep.UntilUnix overflow reaches it) sorts BEFORE every real timestamp AND
// still satisfies "wake_at <= now". It was therefore scanned first on every
// tick, failed to parse, and aborted the whole batch, so no suspended run in
// any tenant ever resumed again. The row persists, so this did not self-heal
// on restart. The supervisor now clamps new rows to maxScheduleHorizon; this
// keeps an already-poisoned table from wedging the daemon.
func TestFindDueSchedulesSkipsUnparseableWakeAt(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.ScheduleSleep(ctx, "run_1", "good", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("schedule sleep: %v", err)
	}
	if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}
	const q = `INSERT INTO schedules (id, run_id, step_name, kind, wake_at, fired)
		VALUES ($1, $2, $3, 'sleep', $4, $5)`
	if _, err := j.db.ExecContext(ctx, j.bind(q),
		"sched_poison", "run_1", "poison", "146138514283-06-19T07:45:04.000Z", j.boolValue(false),
	); err != nil {
		t.Fatalf("insert poison row: %v", err)
	}

	due, err := j.FindDueSchedules(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("FindDueSchedules must not fail on a poisoned row: %v", err)
	}
	if len(due) != 1 || due[0].StepName != "good" {
		names := make([]string, 0, len(due))
		for _, s := range due {
			names = append(names, s.StepName)
		}
		t.Fatalf("want only the good schedule, got %v", names)
	}
}
