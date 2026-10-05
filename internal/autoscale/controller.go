package autoscale

import (
	"context"
	"log/slog"
	"time"
)

// Demand is the queue-depth signal the controller scales against.
type Demand interface {
	CountQueued(ctx context.Context) (int, error)
}

// ClaimableDemand lets a durable queue exclude policy-blocked rows from scale
// decisions while keeping CountQueued as the physical backlog metric. Embedded
// demand sources without this method retain their existing queue-depth signal.
type ClaimableDemand interface {
	CountClaimableQueued(ctx context.Context) (int, error)
}

// SaturatingClaimableDemand lets the controller stop counting once it has
// enough eligible work to request its maximum fleet size. Metrics can still
// call ClaimableDemand for an exact queue depth.
type SaturatingClaimableDemand interface {
	CountClaimableQueuedUpTo(ctx context.Context, saturation int) (int, error)
}

// RunningDemand is an optional companion to Demand. Queue depth alone cannot
// tell the controller whether a worker is still draining an admitted run: a
// worker can have zero queued rows while every slot is executing. When the
// durable demand source implements this interface, scale-down waits for both
// queued and running work to clear. Keeping it optional preserves the small
// in-memory Demand seam used by embedded callers and tests.
type RunningDemand interface {
	CountRunning(ctx context.Context) (int, error)
}

// CapacityDemand reports recently heartbeating worker slots. It lets a small
// backlog add a worker when all existing slots are busy, instead of waiting
// for QueuePerWorker more runs to arrive. The journal implements this seam;
// embedded demand sources may omit it and retain queue-depth-only scaling.
type CapacityDemand interface {
	WorkerCapacity(ctx context.Context, staleAfter time.Duration) (count, capacity int, err error)
}

// Reconciler is implemented by spawners whose workers may exit independently
// of the controller. A failed probe must leave their tracked count unchanged.
type Reconciler interface {
	Reconcile(ctx context.Context) error
}

// Config bounds and paces the autoscaler. The defaults are deliberately
// conservative: Max caps one controller's managed inventory and scale-up is
// gated by a cooldown. Built-in Docker/Kubernetes spawners inventory across
// restarts; process workers drain on parent EOF but may briefly overlap
// replacements after an abrupt parent crash.
type Config struct {
	Min               int           // never go below this many managed workers (default 0 = scale to zero)
	Max               int           // cap for this managed inventory (default 4)
	QueuePerWorker    int           // target queued runs per worker before adding one (default 20)
	ScaleUpCooldown   time.Duration // minimum time between spawns (default 30s)
	ScaleDownCooldown time.Duration // queue + running work must stay empty this long before removing a worker (default 2m)
	Interval          time.Duration // control loop tick (default 15s)
}

func (c *Config) applyDefaults() {
	if c.Max <= 0 {
		c.Max = 4
	}
	if c.Min < 0 {
		c.Min = 0
	}
	if c.Min > c.Max {
		c.Min = c.Max
	}
	if c.QueuePerWorker <= 0 {
		c.QueuePerWorker = 20
	}
	if c.ScaleUpCooldown <= 0 {
		c.ScaleUpCooldown = 30 * time.Second
	}
	if c.ScaleDownCooldown <= 0 {
		c.ScaleDownCooldown = 2 * time.Minute
	}
	if c.Interval <= 0 {
		c.Interval = 15 * time.Second
	}
}

// Controller grows/shrinks a worker pool to track queue depth. Run it on
// ONE instance only (the leader) so there is a single autoscaler.
type Controller struct {
	cfg     Config
	spawner Spawner
	demand  Demand
	log     *slog.Logger
	now     func() time.Time

	lastScaleUp time.Time
	lastBusy    time.Time
	// A probe gap does not prove the pool was idle. Require a fresh full idle
	// window after the first complete observation following any gap.
	idleObservationLost bool
}

// New builds a controller.
func New(cfg Config, spawner Spawner, demand Demand, log *slog.Logger) *Controller {
	cfg.applyDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &Controller{cfg: cfg, spawner: spawner, demand: demand, log: log, now: time.Now}
}

// Run blocks, scaling the pool every Interval until ctx is cancelled, then
// drains every worker it spawned.
func (c *Controller) Run(ctx context.Context) {
	c.log.Info("autoscale: controller started",
		"min", c.cfg.Min, "max", c.cfg.Max, "queue_per_worker", c.cfg.QueuePerWorker,
		"scale_up_cooldown", c.cfg.ScaleUpCooldown.String(), "scale_down_cooldown", c.cfg.ScaleDownCooldown.String())
	c.lastBusy = c.now()
	// Check detached workers before using their count for the initial floor.
	// If the substrate cannot be queried, leave capacity unchanged until a
	// later tick can make a safe decision.
	if err := c.reconcile(ctx); err != nil {
		c.idleObservationLost = true
		c.log.Warn("autoscale: worker probe failed; holding startup scale", "err", err)
	} else {
		for c.spawner.Running() < c.cfg.Min {
			if _, err := c.spawner.Spawn(ctx); err != nil {
				c.log.Warn("autoscale: spawn (min) failed", "err", err)
				break
			}
		}
	}
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.log.Info("autoscale: draining managed workers", "count", c.spawner.Running())
			c.spawner.StopAll(context.Background())
			return
		case <-t.C:
			c.tick(ctx)
		}
	}
}

func (c *Controller) tick(ctx context.Context) {
	if err := c.reconcile(ctx); err != nil {
		// Unknown worker inventory is not proof that the fleet was idle.
		c.lastBusy = c.now()
		c.idleObservationLost = true
		c.log.Warn("autoscale: worker probe failed; holding scale", "err", err)
		return
	}
	countDemand := c.demand.CountQueued
	if bounded, ok := c.demand.(SaturatingClaimableDemand); ok &&
		c.cfg.Max <= int(^uint(0)>>1)/c.cfg.QueuePerWorker {
		// More rows cannot raise the target above Max. Fall back to the exact
		// signal if this product cannot be represented as an int.
		saturation := c.cfg.Max * c.cfg.QueuePerWorker
		countDemand = func(ctx context.Context) (int, error) {
			return bounded.CountClaimableQueuedUpTo(ctx, saturation)
		}
	} else if claimable, ok := c.demand.(ClaimableDemand); ok {
		countDemand = claimable.CountClaimableQueued
	}
	queued, err := countDemand(ctx)
	if err != nil {
		c.lastBusy = c.now()
		c.idleObservationLost = true
		c.log.Warn("autoscale: queue probe failed", "err", err)
		return
	}
	runningWork := 0
	runningKnown := true
	if demand, ok := c.demand.(RunningDemand); ok {
		runningWork, err = demand.CountRunning(ctx)
		if err != nil {
			// A failed in-flight probe is safe for scale-up but unsafe for
			// scale-down: stopping a worker while it owns a run turns a
			// capacity decision into an avoidable lease-recovery event.
			runningKnown = false
			c.lastBusy = c.now()
			c.idleObservationLost = true
			c.log.Warn("autoscale: running-work probe failed; holding scale-down", "err", err)
		}
	}
	running := c.spawner.Running()
	desired := c.desiredWorkers(queued)
	scaleReason := "queue_depth"
	now := c.now()
	if queued > 0 && runningKnown && runningWork > 0 && desired <= running {
		if demand, ok := c.demand.(CapacityDemand); ok {
			_, capacity, probeErr := demand.WorkerCapacity(ctx, 30*time.Second)
			if probeErr != nil {
				// A missing capacity signal cannot prove saturation. Keep the
				// bounded queue-depth target rather than speculatively spawning.
				c.log.Warn("autoscale: worker capacity probe failed; using queue-depth target", "err", probeErr)
			} else if capacity > 0 && runningWork >= capacity && running < c.cfg.Max {
				desired = running + 1
				scaleReason = "saturated_capacity"
			}
		}
	}
	if runningKnown && c.idleObservationLost {
		// The previous idle interval crossed an observation gap. Begin a new
		// interval only once all required probes are healthy again.
		c.lastBusy = now
		c.idleObservationLost = false
	}
	if queued > 0 || (runningKnown && runningWork > 0) {
		c.lastBusy = now
	}

	switch {
	case running < desired:
		// Scale up ONE worker, paced by the cooldown so even sustained load
		// ramps gradually and never bursts past Max.
		if now.Sub(c.lastScaleUp) >= c.cfg.ScaleUpCooldown {
			if id, err := c.spawner.Spawn(ctx); err != nil {
				c.log.Warn("autoscale: scale-up spawn failed", "err", err)
			} else {
				c.lastScaleUp = now
				c.log.Info("autoscale: scaled up", "id", id, "reason", scaleReason, "queued", queued, "running", running+1, "desired", desired, "max", c.cfg.Max)
			}
		}
	case running > desired && running > c.cfg.Min:
		// Scale down ONE worker, but only after the queue has stayed empty
		// for ScaleDownCooldown so we don't flap on brief lulls. If the
		// durable running-work probe is available, require it to be clear as
		// well; queue depth can be zero while every worker slot is busy.
		if !runningKnown || runningWork > 0 {
			return
		}
		if now.Sub(c.lastBusy) >= c.cfg.ScaleDownCooldown {
			ids := c.spawner.IDs()
			if len(ids) > 0 {
				id := ids[len(ids)-1]
				if err := c.spawner.Stop(ctx, id); err != nil {
					c.log.Warn("autoscale: scale-down stop failed; retaining worker", "id", id, "err", err)
					return
				}
				// Stop may request a graceful drain rather than remove the worker
				// immediately. Report the observed count, not an assumed decrement.
				c.log.Info("autoscale: scale-down stop requested", "id", id, "queued", queued, "running", c.spawner.Running(), "desired", desired, "min", c.cfg.Min)
			}
		}
	}
}

func (c *Controller) reconcile(ctx context.Context) error {
	if r, ok := c.spawner.(Reconciler); ok {
		return r.Reconcile(ctx)
	}
	return nil
}

// desiredWorkers is ceil(queued / QueuePerWorker), clamped to [Min, Max].
// An empty queue yields Min (scale to zero when Min is 0).
func (c *Controller) desiredWorkers(queued int) int {
	// Avoid adding QueuePerWorker to a potentially very large queue count:
	// that sum can overflow int and incorrectly scale an overloaded fleet to
	// Min (including zero). Quotient plus remainder computes the same ceiling
	// without exceeding queued.
	d := queued / c.cfg.QueuePerWorker
	if queued%c.cfg.QueuePerWorker != 0 {
		d++
	}
	if d < c.cfg.Min {
		d = c.cfg.Min
	}
	if d > c.cfg.Max {
		d = c.cfg.Max
	}
	return d
}
