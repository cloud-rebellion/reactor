package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
)

func TestReplayWaitsDoNotConsumeHistoricalSchedules(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kind      string
		delivered bool
	}{
		{name: "sleep", kind: journal.KindSleep},
		{name: "delivered signal", kind: journal.KindSignal, delivered: true},
		{name: "expired signal", kind: journal.KindSignal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, j, cleanup := newTestSupervisorEnv(t, "run_replay_wait_"+tc.name)
			defer cleanup()
			sup.Mode = "replay"
			sup.Now = time.Now
			ctx := context.Background()
			var (
				f   wire.Frame
				err error
			)
			if tc.kind == journal.KindSleep {
				if _, err := j.ScheduleSleepSeq(ctx, sup.RunID, "wait", 1, time.Now().Add(-time.Minute)); err != nil {
					t.Fatal(err)
				}
				f, err = wire.Wrap(1, 0, wire.KindSleep, wire.Sleep{StepName: "wait", Seq: 1, UntilUnix: time.Now().Add(time.Hour).Unix()})
			} else {
				deadline := time.Now().Add(-time.Minute)
				if tc.delivered {
					deadline = time.Now().Add(time.Hour)
				}
				if _, err := j.ScheduleSignalSeq(ctx, sup.RunID, "approval", 1, "approval", "sig_replay_wait", deadline); err != nil {
					t.Fatal(err)
				}
				if tc.delivered {
					if _, _, err := j.FireSignal(ctx, "sig_replay_wait", []byte(`{"approved":true}`)); err != nil {
						t.Fatal(err)
					}
				}
				f, err = wire.Wrap(1, 0, wire.KindAwaitSignal, wire.AwaitSignal{StepName: "approval", SignalName: "approval", Seq: 1})
			}
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), writeMu: &sync.Mutex{}}
			if tc.kind == journal.KindSleep {
				err = d.handleSleep(ctx, f)
			} else {
				err = d.handleAwaitSignal(ctx, f)
			}
			if err != nil {
				t.Fatal(err)
			}
			reply, err := wire.NewDecoder(&out).Decode()
			if err != nil {
				t.Fatal(err)
			}
			wantKind := wire.KindAck
			if tc.kind == journal.KindSignal {
				wantKind = wire.KindSignalDeliver
			}
			if reply.Kind != wantKind {
				t.Fatalf("replay reply kind = %q, want %q", reply.Kind, wantKind)
			}
			schedule, err := j.FindScheduleBySeq(ctx, sup.RunID, 1, tc.kind)
			if err != nil || schedule.Fired {
				t.Fatalf("replay consumed historical %s schedule = %+v, %v", tc.kind, schedule, err)
			}
		})
	}
}

func TestReplayRejectsStepEndWithoutMutatingAttempt(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_replay_step_end")
	defer cleanup()
	ctx := context.Background()
	claim, err := j.ClaimStepAttemptSeq(ctx, sup.RunID, "charge", 1, 2, "idem", "hash")
	if err != nil {
		t.Fatal(err)
	}
	sup.Mode = "replay"
	var out bytes.Buffer
	d := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), writeMu: &sync.Mutex{}}
	f, err := wire.Wrap(1, 0, wire.KindStepEnd, wire.StepEnd{
		StepName: "charge", Seq: 1, Attempt: claim.Attempt, DurableAttempts: true,
		Output: json.RawMessage(`{"charged":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handleStepEnd(ctx, f); err == nil {
		t.Fatal("replay accepted a step_end frame")
	}
	if out.Len() != 0 {
		t.Fatalf("replay acknowledged step_end: %s", out.String())
	}
	state, err := j.LatestStepAttemptSeq(ctx, sup.RunID, "charge", 1)
	if err != nil || state.Status != journal.StatusRunning || len(state.Output) != 0 {
		t.Fatalf("replay mutated historical attempt = %+v, %v", state, err)
	}
}
