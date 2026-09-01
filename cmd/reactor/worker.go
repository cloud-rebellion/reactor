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
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file)")
	aclPermissive := fs.Bool("vault-acl-permissive", os.Getenv("REACTOR_VAULT_ACL_PERMISSIVE") == "1", "treat an empty workflow_secret_grants table as allow-all (legacy)")
	cgroupRoot := fs.String("cgroup-root", os.Getenv("REACTOR_CGROUP_ROOT"), "cgroup v2 root for per-run memory.max + pids.max caps")
	concurrency := fs.Int("concurrency", envIntFirst("REACTOR_WORKER_CONCURRENCY", "", runtime.NumCPU()), "max runs this worker executes at once")
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
	if *concurrency < 1 {
		*concurrency = 1
	}
	if *leaseTTL <= 0 {
		return errors.New("worker: --lease-ttl must be greater than zero")
	}
	if *pollInterval <= 0 {
		return errors.New("worker: --poll-interval must be greater than zero")
	}
	if *drainTimeout <= 0 {
		return errors.New("worker: --drain-timeout must be greater than zero")
	}
	masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
	if err != nil {
		return err
	}
	masterKey, err := decodeMasterKey(masterHex)
	if err != nil {
		return err
	}

	cfg := &serveConfig{
		dbURL:            *dbURL,
		root:             *root,
		masterKey:        masterKey,
		aclPermissive:    *aclPermissive,
		cgroupRoot:       *cgroupRoot,
		tickInterval:     5 * time.Second,
		rotationInterval: time.Hour,
		cronReload:       30 * time.Second,
		drainTimeout:     *drainTimeout,
		mode:             "distributed",
	}
	deps, err := openServeDeps(ctx, log, cfg)
	if err != nil {
		return err
	}
	defer deps.db.Close()

	return runWorkerLoop(ctx, log, deps, workerOpts{
		concurrency:  *concurrency,
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

func runWorkerLoop(ctx context.Context, log *slog.Logger, deps *serveDeps, opts workerOpts) error {
	workerID := genWorkerID()
	log.Info("worker: starting", "worker_id", workerID, "concurrency", opts.concurrency, "lease_ttl", opts.leaseTTL.String())

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		log.Info("worker: signal received, shutting down", "signal", s.String())
		cancel()
	}()

	sem := make(chan struct{}, opts.concurrency)
	var wg sync.WaitGroup

	// Register in the worker heartbeat table so the dashboard fleet view +
	// autoscaler see this worker; refresh while running; remove on exit.
	_ = deps.journal.UpsertWorkerHeartbeat(runCtx, workerID, opts.concurrency)
	defer func() {
		_ = deps.journal.DeleteWorker(context.Background(), workerID)
	}()
	go heartbeatWorker(runCtx, deps, workerID, opts.concurrency)

	// Background: requeue dead workers' runs, and honour cross-process
	// cancel requests against this worker's live runs.
	go reaperLoop(runCtx, log, deps, opts.leaseTTL)
	go runCancelWatcher(runCtx, log, deps)

	idle := time.NewTimer(opts.pollInterval)
	defer idle.Stop()
	for runCtx.Err() == nil {
		free := cap(sem) - len(sem)
		if free <= 0 {
			// All slots busy; wait briefly for one to free.
			select {
			case <-runCtx.Done():
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		ids, err := deps.journal.ClaimQueuedRuns(runCtx, workerID, free, opts.leaseTTL)
		if err != nil {
			if runCtx.Err() != nil {
				break
			}
			log.Warn("worker: claim failed", "err", err)
			time.Sleep(opts.pollInterval)
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
		for _, claim := range ids {
			sem <- struct{}{}
			wg.Add(1)
			go func(claim journal.RunLease) {
				defer wg.Done()
				defer func() { <-sem }()
				execCtx, cancelExec := context.WithCancelCause(context.Background())
				hbCtx, stopHeartbeat := context.WithCancel(context.Background())
				hbDone := make(chan error, 1)
				go func() {
					hbDone <- heartbeatLease(hbCtx, deps.journal, claim.RunID, claim.Owner, opts.leaseTTL, cancelExec)
				}()
				execErr := deps.dispatcher.ExecuteRun(execCtx, claim.RunID, claim.Owner)
				stopHeartbeat()
				hbErr := <-hbDone
				cancelExec(context.Canceled)
				if execErr != nil {
					log.Error("worker: execute failed", "run_id", claim.RunID, "err", execErr)
				}
				if hbErr != nil {
					log.Error("worker: lease heartbeat failed; execution cancelled", "run_id", claim.RunID, "err", hbErr)
				}
			}(claim)
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
	log.Info("worker: shutdown complete")
	return nil
}

// heartbeatWorker refreshes this worker's row in the registry so the
// fleet view + autoscaler keep seeing it. Stops with ctx.
func heartbeatWorker(ctx context.Context, deps *serveDeps, workerID string, concurrency int) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = deps.journal.UpsertWorkerHeartbeat(ctx, workerID, concurrency)
		}
	}
}

// reaperLoop periodically requeues runs whose worker died (expired lease).
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
			if n, err := deps.journal.ReapExpiredLeases(ctx); err != nil {
				log.Warn("worker: reap expired leases failed", "err", err)
			} else if n > 0 {
				log.Info("worker: requeued runs from dead workers", "count", n)
			}
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
			err := j.ExtendLease(ctx, runID, owner, leaseTTL)
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
