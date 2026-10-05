package supervisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
)

// TestHandleSleepAcksOnStaleSchedule reproduces the wall-clock-drift bug
// the original handleSleep had: on resume, the workflow body recomputes
// UntilUnix from a fresh time.Now() so the supervisor saw a long wait
// again and re-suspended forever. The fix consults FindLatestSleepSchedule
// before honouring UntilUnix; when the recorded wake_at is in the past
// relative to the supervisor's Now, the frame is acked immediately
// regardless of what the workflow body just computed.
//
// Setup mirrors the bug shape: pre-seed a schedules row whose wake_at
// is in the past, then drive handleSleep with a Sleep frame whose
// UntilUnix is freshly computed and far in the future. Without the fix
// the supervisor writes a fresh schedule + sends Cancel + returns
// errSuspended; with the fix it sends a single Ack frame and returns nil.
func TestHandleSleepAcksOnStaleSchedule(t *testing.T) {
	sup, j, closeDB := newTestSupervisorEnv(t, "run_stale_sleep")
	defer closeDB()

	// Pre-seed the schedule the way a previous suspend would have:
	// wake_at one hour in the past, step name matching the frame below.
	pastWake := time.Now().Add(-time.Hour)
	scheduleID, err := j.ScheduleSleep(context.Background(), "run_stale_sleep", "wait-a", pastWake)
	if err != nil {
		t.Fatalf("seed schedule: %v", err)
	}

	// Pin the supervisor's clock to "now" so wake_at < Now and the
	// resume branch must trigger.
	sup.Now = func() time.Time { return time.Now() }

	// Build a dispatcher wired to in-memory pipes; we only care about
	// what handleSleep writes back, not the workflow process side.
	var outBuf bytes.Buffer
	d := &dispatcher{
		sup:     sup,
		enc:     wire.NewEncoder(&outBuf),
		dec:     wire.NewDecoder(emptyReader{}),
		writeMu: &sync.Mutex{},
	}

	// Fresh-Sleep frame: UntilUnix is a full hour in the future, as the
	// workflow body would compute it on second spawn.
	freshUntil := time.Now().Add(time.Hour).Unix()
	f, err := wire.Wrap(1, 0, wire.KindSleep, wire.Sleep{StepName: "wait-a", UntilUnix: freshUntil})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	if err := d.handleSleep(context.Background(), f); err != nil {
		t.Fatalf("handleSleep returned %v; want nil (ack path)", err)
	}
	if d.suspended.Load() {
		t.Fatalf("dispatcher.suspended = true; resume must not re-suspend on a stale schedule")
	}

	// Decode the single frame the supervisor emitted; it must be Ack.
	dec := wire.NewDecoder(&outBuf)
	got, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if got.Kind != wire.KindAck {
		t.Fatalf("reply kind = %v; want %v (KindAck)", got.Kind, wire.KindAck)
	}
	schedule, err := j.FindLatestSleepSchedule(context.Background(), "run_stale_sleep", "wait-a")
	if err != nil || schedule.ID != scheduleID || !schedule.Fired {
		t.Fatalf("consumed sleep schedule = %+v, %v", schedule, err)
	}
	if due, err := j.FindDueSchedules(context.Background(), time.Now().Add(time.Hour), 10); err != nil || len(due) != 0 {
		t.Fatalf("consumed sleep remained due = %+v, %v", due, err)
	}
}

func TestHandleSleepRejectsOrdinalStepNameDrift(t *testing.T) {
	sup, j, closeDB := newTestSupervisorEnv(t, "run_sleep_drift")
	defer closeDB()
	ctx := context.Background()
	sup.Now = time.Now
	if _, err := j.ScheduleSleepSeq(ctx, sup.RunID, "wait-a", 1, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("seed schedule: %v", err)
	}

	var out bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), dec: wire.NewDecoder(emptyReader{}), writeMu: &sync.Mutex{}}
	f, err := wire.Wrap(1, 0, wire.KindSleep, wire.Sleep{
		StepName:  "wait-b",
		UntilUnix: time.Now().Add(time.Hour).Unix(),
		Seq:       1,
	})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if err := d.handleSleep(ctx, f); !errors.Is(err, ErrReplayDivergence) {
		t.Fatalf("sleep name drift error = %v; want ErrReplayDivergence", err)
	}
	if out.Len() != 0 {
		t.Fatalf("sleep name drift wrote a reply: %d bytes", out.Len())
	}
	schedule, err := j.FindScheduleBySeq(ctx, sup.RunID, 1, journal.KindSleep)
	if err != nil {
		t.Fatalf("read schedule: %v", err)
	}
	if schedule.Fired {
		t.Fatal("sleep name drift consumed the recorded schedule")
	}
}

func TestHandleSleepRejectsOrdinalOperationKindDrift(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_step_to_sleep_drift")
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, sup.RunID, "charge", 1, 1, "idem", "hash"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), dec: wire.NewDecoder(emptyReader{}), writeMu: &sync.Mutex{}}
	f, err := wire.Wrap(1, 0, wire.KindSleep, wire.Sleep{
		StepName: "wait", Seq: 1, UntilUnix: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handleSleep(ctx, f); !errors.Is(err, ErrReplayDivergence) {
		t.Fatalf("step-to-sleep kind drift error = %v, want ErrReplayDivergence", err)
	}
	if out.Len() != 0 {
		t.Fatalf("step-to-sleep kind drift wrote a reply: %d bytes", out.Len())
	}
}

func TestHandleStepStartRejectsOrdinalOperationKindDrift(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_sleep_to_step_drift")
	defer cleanup()
	ctx := context.Background()
	if _, err := j.ScheduleSleepSeq(ctx, sup.RunID, "wait", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), dec: wire.NewDecoder(emptyReader{}), writeMu: &sync.Mutex{}}
	f, err := wire.Wrap(1, 0, wire.KindStepStart, wire.StepStart{
		StepName: "charge", Seq: 1, Attempt: 1, IdempotencyKey: "idem", InputHash: "hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handleStepStart(ctx, f); !errors.Is(err, ErrReplayDivergence) {
		t.Fatalf("sleep-to-step kind drift error = %v, want ErrReplayDivergence", err)
	}
	if out.Len() != 0 {
		t.Fatalf("sleep-to-step kind drift wrote a reply: %d bytes", out.Len())
	}
}

func TestHandleAwaitSignalRetiresDeliveredAndExpiredSchedules(t *testing.T) {
	for _, delivered := range []bool{true, false} {
		name := "expired"
		if delivered {
			name = "delivered"
		}
		t.Run(name, func(t *testing.T) {
			sup, j, closeDB := newTestSupervisorEnv(t, "run_signal_retire_"+name)
			defer closeDB()
			ctx := context.Background()
			expires := time.Now().Add(-time.Minute)
			if delivered {
				expires = time.Now().Add(time.Hour)
			}
			scheduleID, err := j.ScheduleSignal(ctx, sup.RunID, "approval-step", "approval", "token", expires)
			if err != nil {
				t.Fatal(err)
			}
			if delivered {
				if _, _, err := j.FireSignal(ctx, "token", []byte(`{"approved":true}`)); err != nil {
					t.Fatal(err)
				}
			}
			sup.Now = time.Now
			var out bytes.Buffer
			d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), dec: wire.NewDecoder(emptyReader{}), writeMu: &sync.Mutex{}}
			frame, err := wire.Wrap(1, 0, wire.KindAwaitSignal, wire.AwaitSignal{
				StepName: "approval-step", SignalName: "approval", TimeoutMs: int64(time.Hour / time.Millisecond),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := d.handleAwaitSignal(ctx, frame); err != nil {
				t.Fatal(err)
			}
			reply, err := wire.NewDecoder(&out).Decode()
			if err != nil || reply.Kind != wire.KindSignalDeliver {
				t.Fatalf("signal reply = %+v, %v", reply, err)
			}
			schedule, err := j.FindLatestSignalSchedule(ctx, sup.RunID, "approval-step")
			if err != nil || schedule.ID != scheduleID || !schedule.Fired {
				t.Fatalf("consumed signal schedule = %+v, %v", schedule, err)
			}
			if due, err := j.FindDueSchedules(ctx, time.Now().Add(2*time.Hour), 10); err != nil || len(due) != 0 {
				t.Fatalf("consumed signal remained due = %+v, %v", due, err)
			}
		})
	}
}

func TestHandleAwaitSignalRejectsOrdinalIdentityDrift(t *testing.T) {
	sup, j, closeDB := newTestSupervisorEnv(t, "run_signal_drift")
	defer closeDB()
	ctx := context.Background()
	sup.Now = time.Now
	if _, err := j.ScheduleSignalSeq(ctx, sup.RunID, "approval-a", 1, "approve", "token-drift", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("seed schedule: %v", err)
	}
	if _, _, err := j.FireSignal(ctx, "token-drift", []byte(`{"approved":true}`)); err != nil {
		t.Fatalf("seed payload: %v", err)
	}

	var out bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), dec: wire.NewDecoder(emptyReader{}), writeMu: &sync.Mutex{}}
	f, err := wire.Wrap(1, 0, wire.KindAwaitSignal, wire.AwaitSignal{
		StepName:   "approval-b",
		SignalName: "confirm",
		TimeoutMs:  int64(time.Hour / time.Millisecond),
		Seq:        1,
	})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if err := d.handleAwaitSignal(ctx, f); !errors.Is(err, ErrReplayDivergence) {
		t.Fatalf("signal identity drift error = %v; want ErrReplayDivergence", err)
	}
	if out.Len() != 0 {
		t.Fatalf("signal identity drift wrote a reply: %d bytes", out.Len())
	}
	schedule, err := j.FindScheduleBySeq(ctx, sup.RunID, 1, journal.KindSignal)
	if err != nil {
		t.Fatalf("read schedule: %v", err)
	}
	if schedule.Fired {
		t.Fatal("signal identity drift consumed the recorded schedule")
	}
}

func TestHandleAwaitSignalPropagatesFrameEncodingError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		wantErr func(error) bool
	}{
		{
			name:    "invalid-json",
			payload: "{not-json",
			wantErr: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "supervisor: encode delivered signal frame")
			},
		},
		{
			name:    "oversized-frame",
			payload: `"` + strings.Repeat("a", wire.MaxFrameBytes) + `"`,
			wantErr: func(err error) bool { return errors.Is(err, wire.ErrFrameTooLarge) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, j, closeDB := newTestSupervisorEnv(t, "run_signal_encode_"+tc.name)
			defer closeDB()
			ctx := context.Background()
			_, err := j.ScheduleSignal(ctx, sup.RunID, "approval", "approval", "token_encode", time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := j.FireSignal(ctx, "token_encode", []byte(tc.payload)); err != nil {
				t.Fatalf("seed malformed signal payload: %v", err)
			}
			var out bytes.Buffer
			d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), dec: wire.NewDecoder(emptyReader{}), writeMu: &sync.Mutex{}}
			frame, err := wire.Wrap(1, 0, wire.KindAwaitSignal, wire.AwaitSignal{StepName: "approval", SignalName: "approval", TimeoutMs: int64(time.Hour / time.Millisecond)})
			if err != nil {
				t.Fatal(err)
			}
			err = d.handleAwaitSignal(ctx, frame)
			if !tc.wantErr(err) {
				t.Fatalf("handleAwaitSignal error = %v, want encoding failure", err)
			}
			if out.Len() != 0 {
				t.Fatalf("encoding failure wrote a reply frame: %d bytes", out.Len())
			}
		})
	}
}

// emptyReader satisfies the wire.Decoder constructor for the test;
// handleSleep never reads from it.
type emptyReader struct{}

func (emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }
