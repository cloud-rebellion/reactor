package supervisor

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

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

// emptyReader satisfies the wire.Decoder constructor for the test;
// handleSleep never reads from it.
type emptyReader struct{}

func (emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }
