package autoscale

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeSpawner struct {
	mu  sync.Mutex
	ids []string
	seq int
}

func (f *fakeSpawner) Spawn(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := fmt.Sprintf("w%d", f.seq)
	f.ids = append(f.ids, id)
	return id, nil
}
func (f *fakeSpawner) Stop(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, x := range f.ids {
		if x == id {
			f.ids = append(f.ids[:i], f.ids[i+1:]...)
			break
		}
	}
	return nil
}
func (f *fakeSpawner) Running() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.ids) }
func (f *fakeSpawner) IDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}
func (f *fakeSpawner) StopAll(ctx context.Context) {
	for _, id := range f.IDs() {
		_ = f.Stop(ctx, id)
	}
}

type fakeReconciledSpawner struct {
	*fakeSpawner
	reconcileErr error
}

func (f *fakeReconciledSpawner) Reconcile(context.Context) error { return f.reconcileErr }

type fakeDemand struct {
	queued     int
	queuedErr  error
	running    int
	runningErr error
}

type fakeCapacityDemand struct {
	*fakeDemand
	capacity    int
	capacityErr error
}

type fakeClaimableDemand struct {
	*fakeDemand
	claimable int
	err       error
}

type fakeSaturatingClaimableDemand struct {
	*fakeClaimableDemand
	bounded int
	limit   int
	err     error
}

func (d *fakeClaimableDemand) CountClaimableQueued(context.Context) (int, error) {
	return d.claimable, d.err
}

func (d *fakeSaturatingClaimableDemand) CountClaimableQueuedUpTo(_ context.Context, limit int) (int, error) {
	d.limit = limit
	return d.bounded, d.err
}

func (d *fakeCapacityDemand) WorkerCapacity(context.Context, time.Duration) (int, int, error) {
	return 1, d.capacity, d.capacityErr
}

func (d *fakeDemand) CountQueued(context.Context) (int, error) { return d.queued, d.queuedErr }
func (d *fakeDemand) CountRunning(context.Context) (int, error) {
	if d.runningErr != nil {
		return 0, d.runningErr
	}
	return d.running, nil
}

func TestControllerScalesUpGraduallyToMaxThenDown(t *testing.T) {
	sp := &fakeSpawner{}
	dm := &fakeDemand{}
	ctrl := New(Config{Min: 0, Max: 3, QueuePerWorker: 20, ScaleUpCooldown: time.Minute, ScaleDownCooldown: time.Minute}, sp, dm, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	ctrl.lastScaleUp = now.Add(-time.Hour) // cooldown already elapsed
	ctx := context.Background()

	// 100 queued -> desired ceil(100/20)=5, clamped to Max=3, but scale-up
	// is ONE worker per tick gated by the cooldown.
	dm.queued = 100
	ctrl.tick(ctx)
	if sp.Running() != 1 {
		t.Fatalf("first tick: running=%d, want 1 (gradual)", sp.Running())
	}
	// Immediate re-tick is blocked by the scale-up cooldown.
	ctrl.tick(ctx)
	if sp.Running() != 1 {
		t.Fatalf("cooldown should block a second spawn, running=%d", sp.Running())
	}
	// Advance past cooldown each tick -> 2, then 3 (Max), then capped.
	now = now.Add(2 * time.Minute)
	ctrl.tick(ctx)
	now = now.Add(2 * time.Minute)
	ctrl.tick(ctx)
	if sp.Running() != 3 {
		t.Fatalf("running=%d, want 3 (Max)", sp.Running())
	}
	now = now.Add(2 * time.Minute)
	ctrl.tick(ctx)
	if sp.Running() != 3 {
		t.Fatalf("must not exceed Max, running=%d", sp.Running())
	}

	// Queue drains. After the scale-down cooldown (queue empty) workers are
	// removed one per tick down to Min=0.
	dm.queued = 0
	now = now.Add(2 * time.Minute) // lastBusy is now stale by > cooldown
	ctrl.tick(ctx)
	if sp.Running() != 2 {
		t.Fatalf("scale down: running=%d, want 2", sp.Running())
	}
	now = now.Add(2 * time.Minute)
	ctrl.tick(ctx)
	now = now.Add(2 * time.Minute)
	ctrl.tick(ctx)
	if sp.Running() != 0 {
		t.Fatalf("should scale to zero (Min=0), running=%d", sp.Running())
	}
}

func TestControllerScalesFromClaimableDemandInsteadOfBlockedBacklog(t *testing.T) {
	sp := &fakeSpawner{}
	dm := &fakeClaimableDemand{fakeDemand: &fakeDemand{queued: 100, queuedErr: errors.New("raw count must not be used")}}
	ctrl := New(Config{Max: 4, QueuePerWorker: 20}, sp, dm, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	ctrl.lastScaleUp = now.Add(-time.Hour)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 0 {
		t.Fatalf("blocked backlog started %d workers, want none", got)
	}
	dm.claimable = 1
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 1 {
		t.Fatalf("one claimable run started %d workers, want one", got)
	}
	dm.claimable = 0
	dm.err = errors.New("claimable probe unavailable")
	now = now.Add(3 * time.Minute)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 1 {
		t.Fatalf("failed claimable probe stopped worker: %d", got)
	}
}

func TestControllerUsesSaturatingClaimableDemandAtFleetMaximum(t *testing.T) {
	sp := &fakeSpawner{}
	dm := &fakeSaturatingClaimableDemand{
		fakeClaimableDemand: &fakeClaimableDemand{
			fakeDemand: &fakeDemand{queuedErr: errors.New("raw count must not be used")},
			err:        errors.New("exact count must not be used"),
		},
		bounded: 80,
	}
	ctrl := New(Config{Max: 4, QueuePerWorker: 20}, sp, dm, nil)
	ctrl.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	ctrl.tick(context.Background())
	if dm.limit != 80 {
		t.Fatalf("saturation threshold = %d, want 80", dm.limit)
	}
	if got := sp.Running(); got != 1 {
		t.Fatalf("bounded demand started %d workers, want one paced spawn", got)
	}
}

func TestControllerUsesExactDemandWhenSaturationWouldOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	sp := &fakeSpawner{}
	dm := &fakeSaturatingClaimableDemand{
		fakeClaimableDemand: &fakeClaimableDemand{
			fakeDemand: &fakeDemand{queuedErr: errors.New("raw count must not be used")},
			claimable:  maxInt,
		},
		err: errors.New("bounded count must not be used"),
	}
	ctrl := New(Config{Max: maxInt, QueuePerWorker: 2}, sp, dm, nil)
	ctrl.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	ctrl.tick(context.Background())
	if dm.limit != 0 {
		t.Fatalf("overflowing saturation threshold called bounded probe with %d", dm.limit)
	}
	if got := sp.Running(); got != 1 {
		t.Fatalf("large exact demand started %d workers, want one paced spawn", got)
	}
}

func TestControllerRespectsMinFloor(t *testing.T) {
	sp := &fakeSpawner{}
	ctrl := New(Config{Min: 2, Max: 4, ScaleDownCooldown: time.Second}, sp, &fakeDemand{queued: 0}, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	// desiredWorkers(0) must be the Min floor, never below.
	if d := ctrl.desiredWorkers(0); d != 2 {
		t.Fatalf("desired(0)=%d, want Min=2", d)
	}
	if d := ctrl.desiredWorkers(1000); d != 4 {
		t.Fatalf("desired(1000)=%d, want Max=4", d)
	}
}

func TestControllerLargeQueueCountDoesNotOverflowScaleTarget(t *testing.T) {
	sp := &fakeSpawner{}
	dm := &fakeDemand{queued: int(^uint(0) >> 1)}
	ctrl := New(Config{Min: 0, Max: 4, QueuePerWorker: 20}, sp, dm, nil)
	if got := ctrl.desiredWorkers(dm.queued); got != 4 {
		t.Fatalf("desired workers for max int queued = %d, want 4", got)
	}
	ctrl.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 1 {
		t.Fatalf("large queued backlog started %d workers, want one paced spawn", got)
	}
}

func TestControllerDoesNotScaleDownWhileRunsAreStillActive(t *testing.T) {
	sp := &fakeSpawner{}
	_, _ = sp.Spawn(context.Background())
	_, _ = sp.Spawn(context.Background())
	dm := &fakeDemand{queued: 0, running: 1}
	ctrl := New(Config{Min: 0, Max: 4, ScaleDownCooldown: time.Minute}, sp, dm, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	ctrl.lastBusy = now.Add(-time.Hour)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 2 {
		t.Fatalf("active run must hold scale-down, running=%d want 2", got)
	}

	// Once the durable running count clears, the same cooldown permits one
	// worker to drain on each control tick.
	dm.running = 0
	now = now.Add(2 * time.Minute)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 1 {
		t.Fatalf("idle pool should scale down after active work clears, running=%d want 1", got)
	}
}

func TestControllerHoldsScaleDownWhenRunningProbeFails(t *testing.T) {
	sp := &fakeSpawner{}
	_, _ = sp.Spawn(context.Background())
	_, _ = sp.Spawn(context.Background())
	dm := &fakeDemand{runningErr: errors.New("database unavailable")}
	ctrl := New(Config{Min: 0, Max: 4, ScaleDownCooldown: time.Minute}, sp, dm, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	ctrl.lastBusy = now.Add(-time.Hour)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 2 {
		t.Fatalf("probe failure must hold scale-down, running=%d want 2", got)
	}
}

func TestControllerWaitsFullIdleCooldownAfterDemandProbeRecovers(t *testing.T) {
	for _, failure := range []string{"queue", "running"} {
		t.Run(failure, func(t *testing.T) {
			sp := &fakeSpawner{}
			_, _ = sp.Spawn(context.Background())
			_, _ = sp.Spawn(context.Background())
			dm := &fakeDemand{}
			ctrl := New(Config{Min: 0, Max: 4, ScaleDownCooldown: time.Minute}, sp, dm, nil)
			now := time.Unix(1_700_000_000, 0)
			ctrl.now = func() time.Time { return now }
			ctrl.lastBusy = now.Add(-time.Hour)
			if failure == "queue" {
				dm.queuedErr = errors.New("queue count unavailable")
			} else {
				dm.runningErr = errors.New("running count unavailable")
			}
			ctrl.tick(context.Background())
			if got := sp.Running(); got != 2 {
				t.Fatalf("probe failure stopped a worker: %d", got)
			}
			dm.queuedErr, dm.runningErr = nil, nil
			// Recovery happens after the old cooldown has already elapsed.
			// It must begin a new idle window at this observation.
			now = now.Add(90 * time.Second)
			ctrl.tick(context.Background())
			if got := sp.Running(); got != 2 {
				t.Fatalf("probe recovery used stale idle history: %d", got)
			}
			now = now.Add(61 * time.Second)
			ctrl.tick(context.Background())
			if got := sp.Running(); got != 1 {
				t.Fatalf("full idle cooldown did not permit one scale-down: %d", got)
			}
		})
	}
}

func TestControllerWaitsFullIdleCooldownAfterWorkerProbeRecovers(t *testing.T) {
	sp := &fakeReconciledSpawner{fakeSpawner: &fakeSpawner{}, reconcileErr: errors.New("worker inventory unavailable")}
	_, _ = sp.Spawn(context.Background())
	_, _ = sp.Spawn(context.Background())
	ctrl := New(Config{Min: 0, Max: 4, ScaleDownCooldown: time.Minute}, sp, &fakeDemand{}, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	ctrl.lastBusy = now.Add(-time.Hour)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 2 {
		t.Fatalf("worker probe failure stopped a worker: %d", got)
	}
	sp.reconcileErr = nil
	now = now.Add(90 * time.Second)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 2 {
		t.Fatalf("worker probe recovery used stale idle history: %d", got)
	}
	now = now.Add(61 * time.Second)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 1 {
		t.Fatalf("full idle cooldown did not permit one scale-down: %d", got)
	}
}

func TestControllerAddsOneWorkerForSaturatedSmallBacklog(t *testing.T) {
	sp := &fakeSpawner{}
	_, _ = sp.Spawn(context.Background())
	dm := &fakeCapacityDemand{fakeDemand: &fakeDemand{queued: 1, running: 4}, capacity: 4}
	ctrl := New(Config{Min: 0, Max: 2, QueuePerWorker: 20, ScaleUpCooldown: time.Minute}, sp, dm, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	ctrl.lastScaleUp = now.Add(-time.Hour)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 2 {
		t.Fatalf("one queued run behind four occupied slots should add one worker, got %d", got)
	}
	now = now.Add(2 * time.Minute)
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 2 {
		t.Fatalf("saturated fleet exceeded managed max: %d", got)
	}
}

func TestControllerDoesNotTreatUncertainOrSpareCapacityAsSaturation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		capacity int
		err      error
	}{
		{name: "spare slots", capacity: 4},
		{name: "no heartbeat yet", capacity: 0},
		{name: "probe unavailable", err: errors.New("worker registry unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := &fakeSpawner{}
			_, _ = sp.Spawn(context.Background())
			dm := &fakeCapacityDemand{fakeDemand: &fakeDemand{queued: 1, running: 3}, capacity: tc.capacity, capacityErr: tc.err}
			ctrl := New(Config{Max: 3, QueuePerWorker: 20, ScaleUpCooldown: time.Second}, sp, dm, nil)
			now := time.Unix(1_700_000_000, 0)
			ctrl.now = func() time.Time { return now }
			ctrl.lastScaleUp = now.Add(-time.Hour)
			ctrl.tick(context.Background())
			if got := sp.Running(); got != 1 {
				t.Fatalf("uncertain or spare capacity caused speculative spawn: %d", got)
			}
		})
	}
}

func TestControllerRestartsZeroWorkerPoolAfterLeaseRecovery(t *testing.T) {
	sp := &fakeSpawner{}
	dm := &fakeDemand{running: 3}
	ctrl := New(Config{Min: 0, Max: 2, QueuePerWorker: 20, ScaleUpCooldown: time.Second}, sp, dm, nil)
	now := time.Unix(1_700_000_000, 0)
	ctrl.now = func() time.Time { return now }
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 0 {
		t.Fatalf("expired running rows alone started a worker before recovery: %d", got)
	}
	// The elected leader's independent reaper moves expired leases back to
	// queued. The next autoscaler observation must now start a worker even
	// though the managed pool had reached zero.
	dm.running, dm.queued = 0, 3
	ctrl.tick(context.Background())
	if got := sp.Running(); got != 1 {
		t.Fatalf("recovered queued runs did not restart zero-worker fleet: %d", got)
	}
}
