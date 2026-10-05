package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// cmdWorker runs a distributed-mode worker: it claims queued runs from the
// shared Postgres journal (FOR UPDATE SKIP LOCKED), executes each through
// the dispatcher's ExecuteRun, heartbeats the lease while running, and
// reaps leases from dead workers. Run as many as you want against the same
// --db; they share the queue safely. This is how Reactor "duplicates
// itself" to add capacity -- each copy is just another `reactor worker`.
//
//	reactor worker --db postgres://... --root <dir> [--concurrency N]
func cmdWorker(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL (must be postgres:// for distributed mode)")
	root := fs.String("root", defaultRoot(), "Reactor state directory (workflows/ + master.key)")
	artifactRoot := fs.String("artifact-root", os.Getenv("REACTOR_WORKER_ARTIFACT_ROOT"), "separate read-only root containing workflows/ (default: --root)")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file)")
	aclPermissive := fs.Bool("vault-acl-permissive", os.Getenv("REACTOR_VAULT_ACL_PERMISSIVE") == "1", "treat an empty workflow_secret_grants table as same-tenant allow-all (legacy; run identity and tenant checks still apply)")
	cgroupRoot := fs.String("cgroup-root", os.Getenv("REACTOR_CGROUP_ROOT"), "cgroup v2 root for per-run memory.max + pids.max caps")
	requireCgroup := fs.Bool("require-workflow-cgroup", os.Getenv("REACTOR_REQUIRE_WORKFLOW_CGROUP") == "1", "fail a workflow run unless per-run cgroup v2 isolation and cgroup.kill descendant cleanup are available")
	concurrencyRaw := fs.String("concurrency", os.Getenv("REACTOR_WORKER_CONCURRENCY"), "max runs this worker executes at once (1..64; default Go scheduler parallelism, capped at 64)")
	leaseTTL := fs.Duration("lease-ttl", 60*time.Second, "how long a claimed run's lease is valid before a reaper may requeue it (heartbeated while running)")
	pollInterval := fs.Duration("poll-interval", 2*time.Second, "how often to poll for queued work when idle")
	drainTimeout := fs.Duration("drain-timeout", time.Duration(envIntFirst("REACTOR_DRAIN_TIMEOUT", "ARACHNE_DRAIN_TIMEOUT", 30))*time.Second, "max time to wait for in-flight runs on shutdown")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("worker: missing --db (or $REACTOR_DB_URL)")
	}
	if !isPostgresURL(*dbURL) {
		return errors.New("worker: distributed mode requires a postgres:// database")
	}
	concurrency, err := parseWorkerConcurrency(*concurrencyRaw)
	if err != nil {
		return err
	}
	if *leaseTTL < time.Second {
		return errors.New("worker: --lease-ttl must be at least 1s")
	}
	if *pollInterval <= 0 {
		return errors.New("worker: --poll-interval must be greater than zero")
	}
	if *drainTimeout <= 0 {
		return errors.New("worker: --drain-timeout must be greater than zero")
	}
	if err := validateWorkflowCgroupConfig(*cgroupRoot, *requireCgroup); err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
	if err != nil {
		return err
	}
	masterKey, err := decodeMasterKey(masterHex)
	if err != nil {
		return err
	}
	var previousMasterKey []byte
	if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
		previousMasterKey, err = decodeMasterKey(prevHex)
		if err != nil {
			return fmt.Errorf("REACTOR_MASTER_KEY_PREVIOUS: %w", err)
		}
	}

	cfg := &serveConfig{
		dbURL:              *dbURL,
		root:               *root,
		workerArtifactRoot: *artifactRoot,
		masterKey:          masterKey,
		previousMasterKey:  previousMasterKey,
		aclPermissive:      *aclPermissive,
		cgroupRoot:         *cgroupRoot,
		requireCgroup:      *requireCgroup,
		tickInterval:       5 * time.Second,
		rotationInterval:   time.Hour,
		cronReload:         30 * time.Second,
		drainTimeout:       *drainTimeout,
		mode:               "distributed",
	}
	ctx, stopParentGuard, err := workerContextWithParentLiveness(ctx)
	if err != nil {
		return err
	}
	defer stopParentGuard()
	deps, err := openWorkerDeps(ctx, log, cfg)
	if err != nil {
		return err
	}
	defer deps.db.Close()

	return runWorkerLoop(ctx, log, deps, workerOpts{
		concurrency:  concurrency,
		leaseTTL:     *leaseTTL,
		pollInterval: *pollInterval,
		drainTimeout: *drainTimeout,
	})
}

type workerOpts struct {
	concurrency  int
	leaseTTL     time.Duration
	pollInterval time.Duration
	drainTimeout time.Duration
}

func parseWorkerConcurrency(raw string) (int, error) {
	if raw == "" {
		return min(runtime.GOMAXPROCS(0), 64), nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 64 {
		return 0, errors.New("worker: --concurrency (or REACTOR_WORKER_CONCURRENCY) must be an integer between 1 and 64")
	}
	return value, nil
}

// Worker heartbeats are deliberately more frequent than the stale-row
// threshold.  The reaper uses the same threshold as the fleet dashboard, so a
// worker that disappears is removed from both views on the next housekeeping
// pass instead of leaving an ever-growing historical row in the registry.
const (
	workerHeartbeatInterval = 8 * time.Second
	workerHeartbeatTimeout  = 2 * time.Second
	workerStaleAfter        = 30 * time.Second
	// A transient registry write failure should not interrupt healthy work,
	// but continuing indefinitely after the fleet can no longer see this
	// worker would make autoscaling and incident recovery unsafe. Three missed
	// bounded intervals finish before the stale-row threshold in the normal
	// schedule while allowing one or two transient failures to recover.
	workerHeartbeatFailureLimit = 3
)

var errWorkerHeartbeatUnavailable = errors.New("worker: heartbeat registry unavailable")

type workerHeartbeatJournal interface {
	UpsertWorkerHeartbeat(context.Context, string, int) error
}

// registerWorkerHeartbeat is the admission fence for a distributed worker.
// A worker that cannot publish its initial liveness must not claim queue rows:
// the fleet view and autoscaler would otherwise treat it as absent while it
// owns work that needs recovery.
func registerWorkerHeartbeat(ctx context.Context, j workerHeartbeatJournal, workerID string, concurrency int) error {
	if err := j.UpsertWorkerHeartbeat(ctx, workerID, concurrency); err != nil {
		return fmt.Errorf("worker: register heartbeat: %w", err)
	}
	return nil
}

func runWorkerLoop(ctx context.Context, log *slog.Logger, deps *serveDeps, opts workerOpts) error {
	workerID := genWorkerID()
	log.Info("worker: starting", "worker_id", workerID, "concurrency", opts.concurrency, "lease_ttl", opts.leaseTTL.String())

	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	// Register in the worker heartbeat table before starting queue admission.
	// A failed registration is an infrastructure failure; return so the
	// service manager can restart the worker instead of running invisibly.
	if err := registerWorkerHeartbeat(runCtx, deps.journal, workerID, opts.concurrency); err != nil {
		return err
	}
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		heartbeatWorker(runCtx, log, deps.journal, workerID, opts.concurrency, workerHeartbeatInterval, cancel)
	}()
	defer stopWorkerHeartbeatAndUnregister(cancel, heartbeatDone, deps.journal, workerID, log)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case s := <-sigCh:
			log.Info("worker: signal received, shutting down", "signal", s.String())
			cancel(context.Canceled)
		case <-runCtx.Done():
			// Tests and callers can stop a worker without a process signal.
			// Do not retain a blocked signal goroutine or global registration.
		}
	}()

	sem := make(chan struct{}, opts.concurrency)
	var wg sync.WaitGroup

	// Refresh while running. A short outage is logged and tolerated, but
	// repeated failures cancel admission and force a bounded drain so an
	// invisible worker cannot keep owning queue work indefinitely.
	// Background: requeue dead workers' runs, and honour cross-process
	// cancel requests against this worker's live runs.
	go reaperLoop(runCtx, log, deps, opts.leaseTTL)
	go runCancelWatcher(runCtx, log, deps)

	idle := time.NewTimer(opts.pollInterval)
	defer idle.Stop()
	claimStats := workerClaimStats{}
	nextClaimReport := time.Now().Add(time.Minute)
	reportClaims := func(reason string) {
		// Always sample the worker's own pool, including intervals without a
		// claim. A fully occupied worker can still wait on DB connections for
		// step writes while the serving daemon's pool looks healthy.
		claimStats.log(log, workerID, reason, deps.db.Stats())
	}
	for runCtx.Err() == nil {
		if now := time.Now(); !now.Before(nextClaimReport) {
			reportClaims("periodic")
			nextClaimReport = now.Add(time.Minute)
		}
		free := cap(sem) - len(sem)
		if free <= 0 {
			// All slots busy; wait briefly for one to free.
			select {
			case <-runCtx.Done():
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		claimStarted := time.Now()
		ids, err := deps.journal.ClaimQueuedRuns(runCtx, workerID, free, opts.leaseTTL)
		claimStats.record(time.Since(claimStarted), len(ids), err, err != nil && runCtx.Err() != nil)
		if err != nil {
			if runCtx.Err() != nil {
				break
			}
			log.Warn("worker: claim failed", "err", err)
			// A database error must not strand shutdown behind a long polling
			// interval. In particular, Docker's graceful-stop window needs the
			// worker to reach its drain path promptly after SIGTERM.
			select {
			case <-runCtx.Done():
			case <-time.After(opts.pollInterval):
			}
			continue
		}
		if len(ids) == 0 {
			// Idle: wait a poll interval (or until shutdown) before retrying.
			idle.Reset(opts.pollInterval)
			select {
			case <-runCtx.Done():
			case <-idle.C:
			}
			continue
		}
		skipped := launchClaimedBatch(runCtx, ids, func(claim journal.RunLease) {
			sem <- struct{}{}
			wg.Add(1)
			go func(claim journal.RunLease) {
				defer wg.Done()
				defer func() { <-sem }()
				// A signal may arrive after the batch loop checks runCtx but
				// before this goroutine starts. Do not begin a new workflow in
				// that gap; the exact unexecuted lease remains recoverable.
				if runCtx.Err() != nil {
					returnUnstartedClaims(log, deps.journal, []journal.RunLease{claim})
					log.Info("worker: shutdown before claimed run execution", "run_id", claim.RunID)
					return
				}
				execCtx, cancelExec := context.WithCancelCause(context.Background())
				hbCtx, stopHeartbeat := context.WithCancel(context.Background())
				hbDone := make(chan error, 1)
				go func() {
					hbDone <- heartbeatLease(hbCtx, deps.journal, claim.RunID, claim.Owner, opts.leaseTTL, cancelExec)
				}()
				execErr := deps.dispatcher.ExecuteRun(execCtx, claim.RunID, claim.Owner)
				stopHeartbeat()
				hbErr := waitLeaseHeartbeat(hbDone, leaseRenewalTimeout(opts.leaseTTL), cancel)
				cancelExec(context.Canceled)
				if execErr != nil {
					log.Error("worker: execute failed", "run_id", claim.RunID, "err", execErr)
				}
				if hbErr != nil {
					log.Error("worker: lease heartbeat failed; execution cancelled", "run_id", claim.RunID, "err", hbErr)
				}
			}(claim)
		})
		if skipped > 0 {
			returnUnstartedClaims(log, deps.journal, ids[len(ids)-skipped:])
			log.Info("worker: shutdown before starting claimed batch", "skipped", skipped)
		}
	}

	// Close admission before sampling/draining. A claim goroutine that had not
	// entered ExecuteRun yet is rejected and leaves its exact lease recoverable
	// for normal expiry/reaping; it cannot Add after Drain observed zero.
	deps.dispatcher.Stop()
	log.Info("worker: draining in-flight runs", "count", deps.dispatcher.InFlight(), "timeout", opts.drainTimeout.String())
	if err := deps.dispatcher.Drain(opts.drainTimeout); err != nil {
		// A rolling shutdown is infrastructure interruption, not an operator
		// cancelling these runs. Cause-aware cancellation kills the children but
		// makes distributed supervisors retain their running rows and leases so
		// lease expiry + reaping can safely resume them on another worker.
		admissions := deps.dispatcher.CancelAdmissions(cancelreg.ErrInfrastructureShutdown)
		killed := deps.cancels.CancelAllWithCause(cancelreg.ErrInfrastructureShutdown)
		log.Warn("worker: drain timed out; interrupted in-flight runs for recovery", "killed", killed, "admissions", admissions, "err", err)
		_ = deps.dispatcher.Drain(5 * time.Second)
	}
	wg.Wait()
	reportClaims("shutdown")
	log.Info("worker: shutdown complete")
	if cause := context.Cause(runCtx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return nil
}

type unstartedLeaseJournal interface {
	ReturnUnstartedLease(context.Context, string, string) error
}

// Returning never-started claims promptly avoids a full lease-TTL delay on a
// graceful shutdown. If the database is unavailable, the ordinary expiry and
// reaper path remains the fallback. Bound the whole batch so a large claim
// cannot hold shutdown open for one timeout per run.
func returnUnstartedClaims(log *slog.Logger, j unstartedLeaseJournal, claims []journal.RunLease) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, claim := range claims {
		if err := j.ReturnUnstartedLease(ctx, claim.RunID, claim.Owner); err != nil && !errors.Is(err, journal.ErrLeaseOwnershipLost) {
			log.Warn("worker: unstarted claim remains for lease recovery", "run_id", claim.RunID, "err", err)
		}
	}
}

type workerUnregisterJournal interface {
	DeleteWorker(context.Context, string) error
}

// Stop the heartbeat before deleting its registry row. A late upsert after a
// delete would recreate a fresh-looking worker that no longer owns a process,
// misleading both the dashboard and autoscaler. If an uncooperative database
// call does not stop, leave the row to expire instead of racing that upsert.
func stopWorkerHeartbeatAndUnregister(cancel context.CancelCauseFunc, heartbeatDone <-chan struct{}, j workerUnregisterJournal, workerID string, log *slog.Logger) {
	cancel(context.Canceled)
	select {
	case <-heartbeatDone:
	case <-time.After(5 * time.Second):
		log.Warn("worker: heartbeat did not stop; leaving registry row for stale pruning", "worker_id", workerID)
		return
	}
	cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := j.DeleteWorker(cleanupCtx, workerID); err != nil {
		log.Warn("worker: unregister heartbeat failed", "worker_id", workerID, "err", err)
	}
}

// launchClaimedBatch closes the post-claim admission gap: one claim poll may
// return several leases just as shutdown begins. The caller returns the
// unstarted suffix to the queue; starting fresh work during the drain window
// would make shutdown create avoidable side effects.
func launchClaimedBatch(ctx context.Context, claims []journal.RunLease, start func(journal.RunLease)) int {
	started := 0
	for _, claim := range claims {
		if ctx.Err() != nil {
			break
		}
		start(claim)
		started++
	}
	return len(claims) - started
}

// heartbeatWorker refreshes this worker's row in the registry so the
// fleet view + autoscaler keep seeing it. Stops with ctx.
func heartbeatWorker(ctx context.Context, log *slog.Logger, j workerHeartbeatJournal, workerID string, concurrency int, interval time.Duration, cancel context.CancelCauseFunc) {
	if interval <= 0 {
		interval = workerHeartbeatInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	consecutiveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Do not let a stalled database write leave an executing worker
			// registered as healthy only in its own memory. Three 8s ticks with
			// 2s per call fit inside the 30s fleet stale window.
			deadline := min(workerHeartbeatTimeout, max(time.Millisecond, interval/4))
			writeCtx, stop := context.WithTimeout(ctx, deadline)
			// A driver that ignores context cancellation must not keep the
			// worker executing invisibly. Give a normal timeout one extra
			// deadline to return before forcing the worker to drain.
			watch := time.AfterFunc(2*deadline, func() {
				cancel(fmt.Errorf("%w: registry write did not return after deadline", errWorkerHeartbeatUnavailable))
			})
			err := j.UpsertWorkerHeartbeat(writeCtx, workerID, concurrency)
			watch.Stop()
			if err == nil && writeCtx.Err() != nil {
				err = writeCtx.Err()
			}
			stop()
			if err == nil {
				if consecutiveFailures > 0 {
					log.Info("worker: heartbeat recovered", "worker_id", workerID, "missed", consecutiveFailures)
				}
				consecutiveFailures = 0
				continue
			}
			consecutiveFailures++
			log.Warn("worker: heartbeat failed", "worker_id", workerID, "consecutive_failures", consecutiveFailures, "err", err)
			if consecutiveFailures >= workerHeartbeatFailureLimit {
				cancel(fmt.Errorf("%w after %d consecutive failures: %v", errWorkerHeartbeatUnavailable, consecutiveFailures, err))
				return
			}
		}
	}
}

// workerReaperJournal is the small surface needed by one housekeeping pass.
// Keeping it separate from serveDeps makes the lease + worker-row maintenance
// testable without starting a database-backed worker process.
type workerReaperJournal interface {
	ReapExpiredLeases(context.Context) (int64, error)
	PruneStaleWorkers(context.Context, time.Duration) (int64, error)
}

// reapWorkerState requeues expired run leases and removes worker heartbeat rows
// that have gone stale. The two operations are independent: a transient lease
// query error must not prevent registry cleanup, and vice versa.
func reapWorkerState(ctx context.Context, log *slog.Logger, j workerReaperJournal, staleAfter time.Duration) {
	if n, err := j.ReapExpiredLeases(ctx); err != nil {
		log.Warn("worker: reap expired leases failed", "err", err)
	} else if n > 0 {
		log.Info("worker: requeued runs from dead workers", "count", n)
	}
	if n, err := j.PruneStaleWorkers(ctx, staleAfter); err != nil {
		log.Warn("worker: prune stale worker registry failed", "err", err)
	} else if n > 0 {
		log.Info("worker: pruned stale worker registry rows", "count", n)
	}
}

// reaperLoop periodically requeues runs whose worker died (expired lease) and
// prunes the corresponding stale worker heartbeat rows.
func reaperLoop(ctx context.Context, log *slog.Logger, deps *serveDeps, leaseTTL time.Duration) {
	interval := leaseTTL / 3
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reapWorkerState(ctx, log, deps.journal, workerStaleAfter)
		}
	}
}

// heartbeatLease keeps a claimed run's lease fresh while it executes so the
// reaper doesn't requeue a long-but-healthy run. Stops when stop is closed.
type leaseHeartbeatJournal interface {
	ExtendLease(ctx context.Context, runID, owner string, ttl time.Duration) error
	GetRun(ctx context.Context, runID string) (journal.RunInfo, error)
}

var errLeaseHeartbeatUnsafe = errors.New("worker: lease heartbeat lost")

// The database driver should return promptly when stopHeartbeat cancels its
// query. If it does not, do not leave this worker slot (and shutdown) waiting
// forever; stop all new admissions and let the service manager replace it.
func waitLeaseHeartbeat(done <-chan error, timeout time.Duration, cancelWorker context.CancelCauseFunc) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		cause := fmt.Errorf("%w: renewal did not stop after execution", errLeaseHeartbeatUnsafe)
		cancelWorker(cause)
		return cause
	}
}

// A renewal must finish early enough to stop the workflow before the old
// lease can expire and be handed to another worker. The deadline also bounds
// how long a healthy-but-congested database can hold the worker's child alive
// without a confirmed lease extension.
func leaseRenewalTimeout(leaseTTL time.Duration) time.Duration {
	return min(5*time.Second, max(time.Millisecond, leaseTTL/3))
}

func heartbeatLease(ctx context.Context, j leaseHeartbeatJournal, runID, owner string, leaseTTL time.Duration, cancelExec context.CancelCauseFunc) error {
	interval := leaseTTL / 3
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			renewCtx, stop := context.WithTimeout(ctx, leaseRenewalTimeout(leaseTTL))
			// The watchdog cancels execution even if a database driver fails to
			// return when its context expires. A late successful reply cannot
			// resurrect that execution generation.
			watch := context.AfterFunc(renewCtx, func() {
				if errors.Is(renewCtx.Err(), context.DeadlineExceeded) {
					cancelExec(fmt.Errorf("%w: run=%s: renewal deadline exceeded", errLeaseHeartbeatUnsafe, runID))
				}
			})
			err := j.ExtendLease(renewCtx, runID, owner, leaseTTL)
			if err == nil && renewCtx.Err() != nil {
				err = renewCtx.Err()
			}
			watch()
			stop()
			if err == nil {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			cause := fmt.Errorf("%w: run=%s: %v", errLeaseHeartbeatUnsafe, runID, err)
			// Ownership is the only safe authority to keep the child alive. A
			// terminal probe cannot prove this generation produced that outcome:
			// a replacement may have reaped, finished, and released first.
			cancelExec(cause)
			// Finalization atomically writes the terminal/suspended state and
			// deletes the lease. A heartbeat racing just after that commit is a
			// normal heartbeat stop, but the child context is still cancelled because
			// the terminal row may belong to a newer claim generation.
			if errors.Is(err, journal.ErrLeaseOwnershipLost) {
				probeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				run, probeErr := j.GetRun(probeCtx, runID)
				cancel()
				if probeErr == nil && isDurableOutcomeStatus(run.Status) {
					return nil
				}
			}
			return cause
		}
	}
}

func isDurableOutcomeStatus(status string) bool {
	switch status {
	case "succeeded", "failed", "failed_dlq", "cancelled", "suspended":
		return true
	default:
		// queued is especially important here: it means the lease was reaped
		// and a replacement may claim at any moment, so the stale child must die.
		return false
	}
}

// genWorkerID returns a stable-per-process id: hostname-pid-rand.
func genWorkerID() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "worker"
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(b))
}
