// Package supervisor runs a single workflow subprocess, dispatches its
// wire-protocol frames, and persists step outcomes into the journal so
// the workflow can survive mid-step host restarts.
//
// One Supervisor per run. The supervisor spawns the workflow binary,
// wires its stdin + stdout, sends the Hello frame, and then loops:
//
//	wf -> step_start  -> host checks journal -> reply proceed | replay
//	wf -> step_end    -> host writes journal -> reply ack
//	wf -> sleep       -> host blocks (short) or suspends (long, week 4) -> ack
//	wf -> secret_fetch -> host reads vault   -> reply with bytes
//	wf -> log         -> host forwards to slog (no reply)
//
// On EOF (workflow exits), the supervisor marks the run terminal
// (succeeded if last step succeeded, failed otherwise).
package supervisor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/vault"
)

// VaultReader is the metadata + value surface the supervisor needs from the
// vault. Defined locally so the supervisor doesn't drag in the rotation
// scheduler or rotator interfaces.
type VaultReader interface {
	Get(ctx context.Context, id string) (*vault.Secret, error)
}

// OAuthTokenResolver returns a fresh access token for a connection id scoped to
// a tenant. Satisfied by *oauth.Store; an interface here so the supervisor
// package doesn't import internal/oauth.
type OAuthTokenResolver interface {
	Token(ctx context.Context, connectionID, tenantID string) (string, error)
	RawToken(ctx context.Context, connectionID, tenantID string) (string, error)
	ConnectionProvider(ctx context.Context, connectionID, tenantID string) (string, error)
	RawTokenAllowed(ctx context.Context, connectionID, tenantID string) (bool, error)
	SalesforceBrokerSession(ctx context.Context, connectionID, tenantID string) (token, origin, accountKey string, err error)
	SalesforceBrokerSessionCurrent(ctx context.Context, connectionID, tenantID, token, origin, accountKey string) (bool, error)
	GenericBrokerSession(ctx context.Context, tenantID, connectionID string) (oauth.BrokerSession, error)
	BrokerPolicyCurrent(ctx context.Context, session oauth.BrokerSession) (bool, error)
	ConnectionActive(ctx context.Context, tenantID, connectionID, providerID string) (bool, error)
}

// Supervisor wires a journal + vault + a workflow binary into a running
// workflow.
type Supervisor struct {
	BinaryPath   string
	WorkflowSlug string
	RunID        string
	Mode         string // "live" | "replay" | "dry_run"
	Journal      *journal.Journal
	Vault        VaultReader
	// OAuthTokens resolves an `oauth:<connection-id>` secret request to a
	// fresh access token (refreshing if needed), scoped to the run's tenant.
	// nil disables oauth: resolution.
	OAuthTokens OAuthTokenResolver
	// connectorHTTPClient is a package-local test seam. Production always uses
	// the shared safehttp transport, which pins the public-IP policy at dial.
	connectorHTTPClient *http.Client
	Log                 *slog.Logger

	// SignalSigningKey is the root secret (the vault master key) used to derive
	// a per-run signing key for AwaitSignal capability tokens. Set from the
	// master key at wiring time. Empty falls back to the legacy runID-only
	// derivation (used by tests without a vault); production always sets it so
	// the token is unforgeable by anyone who only knows the semi-public runID.
	SignalSigningKey []byte

	// Input is the JSON-encoded trigger payload. Surfaced to the
	// workflow via the REACTOR_INPUT env var so sdk/runtime.Serve's
	// generic Input I decode finds it. Empty means the workflow
	// receives the zero value.
	Input []byte

	// ExtraEnv is appended to the child allowlist when spawning the child.
	// Tests inject test-only env vars (FF_TEST_RECORD, etc.) here so they
	// survive across spawns without polluting the parent process. Secret and
	// HOME overrides are rejected by childEnv.
	ExtraEnv []string

	// SuspendThreshold is the cutoff for short-vs-long sleeps. A Sleep
	// frame with wake_at <= now + threshold blocks the supervisor in
	// place; anything longer is upgraded to suspend-and-resume: a
	// schedules row is written, the workflow process is asked to cancel,
	// and the scheduler re-spawns it at wake_at. Default 30s.
	SuspendThreshold time.Duration

	// Optional clock override for tests. Ignored by the kernel sleep
	// itself; only used to evaluate UntilUnix vs threshold and for
	// schedule timestamps.
	Now func() time.Time

	// LogSink optionally receives workflow-emitted log lines (Log
	// frames from the workflow process + the workflow's stderr). The
	// daemon wires this to internal/runlogs.Buffer.Append so the
	// dashboard's /runs/{id}/tail SSE shows the workflow's own logs
	// alongside dispatcher status lines. Nil means logs only reach
	// the slog sink.
	LogSink func(runID, line string)

	// Limits caps the workflow subprocess via prlimit(2) on Linux.
	// Zero fields fall back to DefaultResourceLimits. Non-Linux GOOS
	// values are no-op (operators rely on the outer container/VM).
	Limits ResourceLimits

	// ACLPermissive controls how workflow_secret_grants emptiness is
	// interpreted. false (default): empty table denies every fetch,
	// forcing operators to explicitly grant credentials per workflow.
	// true: empty table allows same-tenant fetches (the legacy v0 behaviour;
	// kept for migration scenarios via REACTOR_VAULT_ACL_PERMISSIVE=1). Run
	// identity and tenant ownership checks always remain enforced.
	ACLPermissive bool

	// LeaseOwner is the opaque per-claim generation assigned by the
	// distributed queue. When set, every run-state transition is fenced by
	// this exact owner and committed atomically with releasing its lease.
	// Empty means local/replay execution and preserves the single-node path.
	LeaseOwner string
}

// ErrRunRecoverable tells a distributed worker that the child process died at
// a durable running/retrying step boundary. The run intentionally remains
// running with its lease intact; normal expiry + reaping will enqueue a fresh
// supervisor which consumes the durable retry budget.
var ErrRunRecoverable = errors.New("supervisor: workflow process crashed at a recoverable step boundary")

// ErrDeadLetterRepairRecoverable tags a failed exact-DLQ repair. Even when the
// database error happened before StatusDLQPending could be committed, a leased
// worker must leave the run/lease intact for expiry and repair retry.
var ErrDeadLetterRepairRecoverable = errors.New("supervisor: exact dead-letter repair is recoverable")

// Run spawns the workflow binary and dispatches its frames until EOF or
// ctx cancellation. Returns the run's terminal status.
func (s *Supervisor) Run(ctx context.Context) (status string, runErr error) {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.SuspendThreshold == 0 {
		s.SuspendThreshold = 30 * time.Second
	}
	status = "failed"
	forceLocalRecovery := false
	// A single exit funnels every path (including stdin/stdout/start/hello
	// failures and panics) through durable state persistence. Returning an
	// empty status means no transition committed, so callers must not fire
	// terminal hooks.
	defer func() {
		if rec := recover(); rec != nil {
			status = "failed"
			runErr = errors.Join(runErr, fmt.Errorf("supervisor: panic: %v", rec))
		}
		if s.Mode == "replay" || status == "" {
			return
		}
		if ctx.Err() != nil {
			// A non-standard cancellation cause is the distributed heartbeat
			// declaring this lease unsafe. Do not convert that into an operator
			// cancellation or release the possibly-replaced lease.
			cause := context.Cause(ctx)
			if cause != nil && !errors.Is(cause, context.Canceled) {
				if s.LeaseOwner != "" {
					status = ""
					runErr = errors.Join(runErr, fmt.Errorf("supervisor: execution ownership became unsafe: %w", cause))
					return
				}
				// Local drain timeout is a controlled infrastructure stop, not
				// operator intent. Even before the first durable StepStart, park a
				// synthetic recovery schedule for the next healthy daemon.
				status = "failed"
				forceLocalRecovery = true
				runErr = errors.Join(runErr, fmt.Errorf("supervisor: infrastructure stop: %w", cause))
			} else {
				status = "cancelled"
			}
		}

		durableCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		persistedStatus, err := s.persistOutcomeStatus(durableCtx, status, forceLocalRecovery)
		if err != nil {
			persistErr := fmt.Errorf("supervisor: persist run outcome: %w", err)
			status = ""
			runErr = errors.Join(runErr, persistErr)
			// Local runs have no lease whose expiry can recover a failed
			// terminal write. If the final status transaction loses a transient
			// database race (or the commit result is uncertain), leaving the row
			// in `running` strands it until a full daemon restart, because the
			// orphan classifier intentionally runs only at startup. Park an
			// explicit, due recovery schedule while the process is still alive.
			// RecoverLocalInterruptedRun is fenced by the run row and is
			// idempotent: if the original transaction actually committed, it
			// observes the terminal row and does nothing; if it did not, the
			// next scheduler tick replays the durable boundary.
			if s.LeaseOwner == "" && s.Journal != nil {
				recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 5*time.Second)
				recoveredStatus, recoveryErr := s.Journal.RecoverLocalInterruptedRun(recoveryCtx, s.RunID, true)
				recoveryCancel()
				if recoveryErr != nil {
					runErr = errors.Join(runErr, fmt.Errorf("supervisor: park local recovery after outcome persistence failure: %w", recoveryErr))
				} else if recoveredStatus != "" {
					status = recoveredStatus
				}
			}
		} else {
			status = persistedStatus
		}
	}()

	// Keep os/exec's context watcher dormant: it can race a concurrent Wait
	// and send a process-group signal after the group leader was reaped. The
	// supervisor below watches ctx and joins that watcher before its sole Wait.
	cmd := exec.CommandContext(context.Background(), s.BinaryPath)
	// Ensure a daemon crash cannot leave the workflow process running against a
	// closed journal or stale credentials. Linux applies this as a parent-death
	// signal; other platforms keep their existing outer-process supervision.
	configureChildProcess(cmd)
	// The child workflow runs untrusted, operator-or-AI-authored code. It
	// must NOT inherit the daemon's full environment: os.Environ() would
	// hand it REACTOR_MASTER_KEY + REACTOR_DB_URL, letting any workflow
	// decrypt the entire vault and bypass the per-workflow secret ACL.
	// Secrets reach the workflow only over the wire protocol's
	// secret_fetch frame (gated by HasGrant). So we build the child env
	// from an explicit allowlist of harmless system vars plus the one
	// input var and any test-injected ExtraEnv.
	// Do not let untrusted workflow code inherit the daemon's working
	// directory. The daemon is commonly started from its state or deployment
	// directory, and relative file access would otherwise expose unrelated
	// operator files. Give each run a private scratch directory instead.
	workDir, err := os.MkdirTemp("", "reactor-run-")
	if err != nil {
		return "failed", fmt.Errorf("supervisor: create workflow working directory: %w", err)
	}
	defer os.RemoveAll(workDir)
	cmd.Dir = workDir
	// PWD is metadata, but it is still an information leak: inherited PWD
	// commonly points at the daemon's state/deployment directory. Keep the
	// child process' view consistent with cmd.Dir without exposing that path.
	// Keep all conventional temporary-directory variables inside the same
	// per-run directory. Inheriting TMPDIR/TMP/TEMP would let an otherwise
	// filesystem-limited workflow inspect files left by the daemon or another
	// run when the host uses a shared temporary directory. These keys are
	// deliberately omitted from childEnvAllowlist below so the child receives
	// exactly one value for each variable.
	cmd.Env = childEnvForWorkDir(s.Input, s.ExtraEnv, workDir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "failed", fmt.Errorf("supervisor: stdin: %w", err)
	}
	// Own stdout rather than using Cmd.StdoutPipe: the latter forbids calling
	// Wait while the decoder reads. A workflow may exit after forking a child
	// that inherits stdout, in which case waiting for decoder EOF first would
	// block forever. An owned pipe lets a non-reaping exit observer put a
	// deadline on any inherited output handle before the sole Cmd.Wait.
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		return "failed", fmt.Errorf("supervisor: stdout: %w", err)
	}
	defer stdout.Close()
	defer stdoutWriter.Close()
	cmd.Stdout = stdoutWriter
	cmd.Stderr = newStderrForwarder(s.Log)
	// Cmd.Wait also waits for the stderr forwarder to reach EOF. A forked
	// descendant can inherit stderr as well, so bound that copy after the
	// direct process exits; it is a protocol failure, not successful output.
	cmd.WaitDelay = childExitPipeWait

	// Optional cgroup v2 layer. Linux + /sys/fs/cgroup mounted as v2 +
	// daemon has write perms = the child clone3()s straight into a
	// per-run cgroup with memory.max + pids.max preset; the noop path
	// returns Fd=-1 and we still get prlimit enforcement below.
	cgroup := prepareCgroup(s.Log, s.RunID, s.Limits)
	defer closeCgroupHandle(cgroup)
	if s.Limits.RequireCgroup && (s.Limits.CgroupRoot == "" || cgroup.Fd < 0 || !cgroup.Killable) {
		return "failed", fmt.Errorf("supervisor: workflow cgroup isolation is required but unavailable (root=%q, fd=%d, descendant_cleanup=%t)", s.Limits.CgroupRoot, cgroup.Fd, cgroup.Killable)
	}
	if cgroup.Fd >= 0 {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		applyCgroupToSysProcAttr(cmd.SysProcAttr, cgroup)
	}

	if err := ctx.Err(); err != nil {
		return "failed", err
	}
	if err := cmd.Start(); err != nil {
		return "failed", fmt.Errorf("supervisor: start: %w", err)
	}
	_ = stdoutWriter.Close()
	// Panics in a dispatcher callback are recovered by the outer outcome
	// persistence defer. Reap the child before that defer runs, otherwise a
	// recovered panic can leave the workflow executing after its run failed.
	var monitor childExitMonitor
	var monitorStarted, observerConsumed, childWaited bool
	var stopCancelWatcher, cancelWatcherDone chan struct{}
	var watcherStarted bool
	var stopWatcherOnce sync.Once
	stopWatcher := func() {
		if !watcherStarted {
			return
		}
		stopWatcherOnce.Do(func() { close(stopCancelWatcher) })
		<-cancelWatcherDone
	}
	defer func() {
		if childWaited {
			return
		}
		_ = killChildProcess(cmd)
		_ = stdin.Close()
		if monitorStarted {
			if !observerConsumed {
				<-monitor.observed
			}
			stopWatcher()
			_ = monitor.wait()
		} else {
			_ = cmd.Wait()
		}
	}()

	if err := applyRlimits(cmd.Process.Pid, s.Limits); err != nil {
		s.Log.Warn("supervisor: rlimit apply failed", "err", err)
	}

	processExited := make(chan struct{})
	outputReader := &childOutputReader{pipe: stdout, processExited: processExited}
	disp := &dispatcher{
		sup:     s,
		enc:     wire.NewEncoder(stdin),
		dec:     wire.NewDecoder(outputReader),
		writeMu: &sync.Mutex{},
	}

	if err := disp.sendHello(); err != nil {
		_ = killChildProcess(cmd)
		_ = cmd.Wait()
		childWaited = true
		return "failed", fmt.Errorf("supervisor: hello: %w", err)
	}
	monitor = startChildExitMonitor(cmd, func(observeErr error) {
		if observeErr == nil {
			// The group leader is still unreaped on Unix. Clean descendants
			// before its PID can be reused, even if they closed both pipes.
			cleanupChildGroupAfterExit(cmd)
		}
		outputReader.absoluteDeadline = time.Now().Add(childExitOutputMaxDrain)
		// A read already blocked in the decoder needs its deadline set here.
		// Future reads refresh the idle deadline in childOutputReader.
		if err := stdout.SetReadDeadline(time.Now().Add(childExitOutputIdleTimeout)); err != nil {
			_ = stdout.Close()
		}
		close(processExited)
	})
	monitorStarted = true
	stopCancelWatcher = make(chan struct{})
	cancelWatcherDone = make(chan struct{})
	go func() {
		defer close(cancelWatcherDone)
		select {
		case <-ctx.Done():
			_ = killChildProcess(cmd)
		case <-stopCancelWatcher:
		}
	}()
	watcherStarted = true

	loopErr := disp.loop(ctx)
	suspending := errors.Is(loopErr, errSuspended)
	if suspending {
		loopErr = nil // not an error; it's a clean suspend
	}
	// An abnormal protocol exit or durable suspension must stop the child
	// before Wait. Otherwise a workflow that ignores stdin or forks a helper
	// can keep the supervisor and scheduler drain blocked indefinitely.
	if suspending || (loopErr != nil && !errors.Is(loopErr, io.EOF)) {
		if err := killChildProcess(cmd); err != nil && !errors.Is(err, os.ErrProcessDone) {
			s.Log.Warn("supervisor: stop workflow process group", "err", err)
		}
	}

	closeErr := stdin.Close()
	var observerErr error
	closedOutputBeforeExit := false
	if errors.Is(loopErr, io.EOF) {
		// EOF is only a clean workflow exit if the direct process also exits.
		// A child can close stdout and keep running forever without emitting
		// another frame; give its normal teardown a short grace, then stop it.
		timer := time.NewTimer(childExitAfterEOFGrace)
		select {
		case observerErr = <-monitor.observed:
		case <-timer.C:
			closedOutputBeforeExit = true
			_ = killChildProcess(cmd)
			observerErr = <-monitor.observed
		}
		timer.Stop()
	} else {
		observerErr = <-monitor.observed
	}
	observerConsumed = true
	if observerErr != nil {
		_ = killChildProcess(cmd)
	}
	stopWatcher()
	waitErr := monitor.wait()
	childWaited = true

	terminal := "succeeded"
	var executionErr error
	if loopErr != nil && !errors.Is(loopErr, io.EOF) {
		terminal = "failed"
		executionErr = errors.Join(executionErr, loopErr)
	}
	if observerErr != nil {
		terminal = "failed"
		executionErr = errors.Join(executionErr, fmt.Errorf("supervisor: observe workflow exit: %w", observerErr))
	}
	if closedOutputBeforeExit {
		terminal = "failed"
		executionErr = errors.Join(executionErr, errors.New("supervisor: workflow closed protocol output before process exit"))
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) && !exitErr.Success() {
			terminal = "failed"
		} else if !errors.As(waitErr, &exitErr) {
			terminal = "failed"
			executionErr = errors.Join(executionErr, fmt.Errorf("supervisor: wait for workflow: %w", waitErr))
		}
	}
	// If the dispatcher upgraded a long Sleep to a suspend, the run is
	// not terminal; it stays in "suspended" state and the scheduler will
	// re-spawn at wake_at. Don't overwrite that with succeeded/failed.
	if disp.suspended.Load() {
		return "suspended", nil
	}
	if disp.deadLetter.Load() {
		terminal = "failed_dlq"
	}
	if closeErr != nil && !errors.Is(closeErr, io.ErrClosedPipe) && !errors.Is(closeErr, os.ErrClosed) {
		s.Log.Warn("supervisor: stdin close", "err", closeErr)
	}

	// A child crash after a durable step_start/Retryable step_end is safe to
	// replay. In distributed mode keep both run and lease recoverable; the
	// heartbeat stops when ExecuteRun returns and the reaper later queues it.
	// Early launch/hello failures have no such checkpoint and remain terminal.
	if s.LeaseOwner != "" && terminal == "failed" && ctx.Err() == nil {
		if errors.Is(executionErr, ErrDeadLetterRepairRecoverable) {
			return "", errors.Join(executionErr, waitErr, ErrRunRecoverable)
		}
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		recoverable, probeErr := s.Journal.HasRecoverableStepAttempt(probeCtx, s.RunID)
		cancel()
		if probeErr != nil {
			return "", errors.Join(executionErr, waitErr, probeErr)
		}
		if recoverable {
			return "", errors.Join(executionErr, waitErr, ErrRunRecoverable)
		}
	}
	return terminal, executionErr
}

// PersistOutcome is the only run-state writer used by Supervisor.Run. Replay
// mode calls neither this method nor any other state writer. Distributed runs
// use the lease-owned atomic transition; local runs retain the established
// journal APIs but now propagate their errors instead of logging false success.
func (s *Supervisor) PersistOutcome(ctx context.Context, status string) error {
	_, err := s.PersistOutcomeStatus(ctx, status)
	return err
}

// PersistOutcomeStatus returns the status that actually committed. A failed
// process before the first redrive StepStart atomically restores the exact
// authorization and persists failed_dlq, rather than stranding the run as
// failed with an unusable StatusRedrive marker.
func (s *Supervisor) PersistOutcomeStatus(ctx context.Context, status string) (string, error) {
	return s.persistOutcomeStatus(ctx, status, false)
}

func (s *Supervisor) persistOutcomeStatus(ctx context.Context, status string, forceLocalRecovery bool) (string, error) {
	if s.Journal == nil {
		return "", errors.New("supervisor: journal is nil")
	}
	if status == "failed" {
		var (
			recovered bool
			err       error
		)
		if s.LeaseOwner != "" {
			recovered, err = s.Journal.RecoverOwnedPendingDeadLetterRedrive(ctx, s.RunID, s.LeaseOwner)
		} else {
			return s.Journal.RecoverLocalInterruptedRun(ctx, s.RunID, forceLocalRecovery)
		}
		if err != nil {
			return "", err
		}
		if recovered {
			return "failed_dlq", nil
		}
	}
	if s.LeaseOwner != "" {
		return status, s.Journal.FinalizeOwnedRun(ctx, s.RunID, s.LeaseOwner, status)
	}
	switch status {
	case "suspended":
		return status, s.Journal.SetRunStatus(ctx, s.RunID, status)
	case "cancelled":
		return status, s.Journal.FinalizeCancel(ctx, s.RunID)
	default:
		return status, s.Journal.MarkRunFinishedForMode(ctx, s.RunID, status, s.Mode == "dry_run")
	}
}

// dispatcher owns one live workflow connection.
type dispatcher struct {
	sup               *Supervisor
	enc               *wire.Encoder
	dec               *wire.Decoder
	writeMu           *sync.Mutex
	frames            atomic.Int64
	suspended         atomic.Bool // set when a long Sleep upgrades to suspend
	deadLetter        atomic.Bool // set when a step's final attempt failed and was DLQ'd
	blockTenant       string
	blockDeclarations map[string]map[string]flowblocks.Block
}

func (d *dispatcher) sendHello() error {
	f, err := wire.Wrap(d.nextID(), 0, wire.KindHello, wire.Hello{
		Version:         wire.Version,
		WorkflowSlug:    d.sup.WorkflowSlug,
		RunID:           d.sup.RunID,
		Mode:            d.sup.Mode,
		SignalKey:       perRunSignalKey(d.sup.SignalSigningKey, d.sup.RunID),
		ObservedBlocks:  true,
		ConnectorBroker: true,
		MailBroker:      true,
	})
	if err != nil {
		return err
	}
	return d.write(f)
}

func (d *dispatcher) loop(ctx context.Context) error {
	for {
		f, err := d.dec.Decode()
		if err != nil {
			return err
		}
		switch f.Kind {
		case wire.KindHello:
			// First frame from workflow: confirms protocol match. Nothing else.
		case wire.KindStepStart:
			if err := d.handleStepStart(ctx, f); err != nil {
				return err
			}
		case wire.KindStepEnd:
			if err := d.handleStepEnd(ctx, f); err != nil {
				return err
			}
		case wire.KindBlockReceipt:
			if err := d.handleBlockReceipt(ctx, f); err != nil {
				return err
			}
		case wire.KindSleep:
			if err := d.handleSleep(ctx, f); err != nil {
				return err
			}
		case wire.KindAwaitSignal:
			if err := d.handleAwaitSignal(ctx, f); err != nil {
				return err
			}
		case wire.KindSecretFetch:
			if err := d.handleSecretFetch(ctx, f); err != nil {
				return err
			}
		case wire.KindConnectorRequest:
			if err := d.handleConnectorRequest(ctx, f); err != nil {
				return err
			}
		case wire.KindMailSendRequest:
			if err := d.handleMailSendRequest(ctx, f); err != nil {
				return err
			}
		case wire.KindLog:
			d.handleLog(f)
		default:
			// The child controls Kind, too. Do not promote its bytes into the
			// host log or a shared log shipper through this diagnostic path.
			d.sup.Log.Warn("supervisor: unknown frame kind")
		}
	}
}

// handleBlockReceipt checks the exact immutable declaration and the running
// step attempt before acknowledging a value-free SDK report. This establishes
// identity and bounds, not tamper-proof evidence of arbitrary child behavior.
func (d *dispatcher) handleBlockReceipt(ctx context.Context, f wire.Frame) error {
	if d.sup.Mode == "replay" {
		return errors.New("supervisor: observed blocks cannot be written during replay")
	}
	var body wire.BlockReceipt
	if err := wire.Unwrap(f, &body); err != nil {
		return err
	}
	receipt := journal.BlockReceipt{
		RunID: d.sup.RunID, StepName: body.StepName, Seq: body.Seq,
		Attempt: body.Attempt, CallOrdinal: body.CallOrdinal, BlockID: body.BlockID,
		Kind: body.Kind, Mode: body.Mode, LeftRows: body.LeftRows,
		RightRows: body.RightRows, OutputRows: body.OutputRows,
		MaxRows: body.MaxRows, InputRows: body.InputRows, YesRows: body.YesRows,
		NoRows: body.NoRows, Outcome: body.Outcome,
	}
	if body.Seq < 1 || body.Attempt < 1 ||
		body.CallOrdinal < 1 || body.CallOrdinal > 128 ||
		!journal.ValidBlockReceiptShape(receipt) {
		return errors.New("supervisor: invalid observed block metadata")
	}
	if err := d.loadBlockDeclarations(ctx); err != nil {
		return err
	}
	declared, ok := d.blockDeclarations[body.StepName][body.BlockID]
	if !ok || declared.Kind != body.Kind ||
		(body.Kind == "merge" && (declared.Mode != body.Mode || declared.MaxRows != body.MaxRows)) ||
		((body.Kind == "split" || body.Kind == "iterate" || body.Kind == "aggregate") &&
			(declared.Mode != "" || declared.MaxRows != 0)) {
		return errors.New("supervisor: observed block does not match the pinned visual declaration")
	}
	if err := d.sup.Journal.AppendBlockReceipt(ctx, d.blockTenant, d.sup.LeaseOwner, receipt); err != nil {
		return fmt.Errorf("supervisor: persist observed block: %w", err)
	}
	ack, err := wire.Wrap(d.nextID(), f.ID, wire.KindAck, nil)
	if err != nil {
		return err
	}
	return d.write(ack)
}

func (d *dispatcher) loadBlockDeclarations(ctx context.Context) error {
	if d.blockDeclarations != nil {
		return nil
	}
	info, err := d.sup.Journal.GetRunForTenantMetadata(ctx, d.sup.RunID, "", 0)
	if err != nil {
		return fmt.Errorf("supervisor: load observed block run identity: %w", err)
	}
	if info.WorkflowVersion < 1 || info.WorkflowArtifactSHA256 == "" {
		return errors.New("supervisor: observed block requires an immutable run artifact")
	}
	// Authoring, MCP, and dashboard accept this same bounded DAG size. A
	// workflow accepted there must not fail only when its SDK emits a receipt.
	const maxObservedDAGBytes = 1 << 20
	version, err := d.sup.Journal.WorkflowVersionAtBounded(ctx, info.WorkflowID, info.WorkflowVersion, maxObservedDAGBytes)
	if err != nil {
		return fmt.Errorf("supervisor: load observed block declaration: %w", err)
	}
	if version.DAGTruncated || version.ArtifactSHA256 != info.WorkflowArtifactSHA256 {
		return errors.New("supervisor: observed block declaration is unavailable or artifact identity changed")
	}
	projection := flowblocks.FromDAG(version.DAG, maxObservedDAGBytes)
	if !projection.Complete || projection.Provenance != "author_declared_annotation" {
		return errors.New("supervisor: observed block requires a valid visual declaration")
	}
	declared := make(map[string]map[string]flowblocks.Block, len(projection.Steps))
	for _, step := range projection.Steps {
		blocks := make(map[string]flowblocks.Block, len(step.Blocks))
		for _, block := range step.Blocks {
			blocks[block.ID] = block
		}
		declared[step.Step] = blocks
	}
	d.blockTenant = info.TenantID
	d.blockDeclarations = declared
	return nil
}

// verifyRecordedCall binds every ordinal-aware SDK operation to the same
// durable call identity, even though steps and suspended waits live in separate
// journal tables. A changed kind must fail before it can execute a new step or
// consume/create a wait at an ordinal the prior process already reached.
func (d *dispatcher) verifyRecordedCall(ctx context.Context, seq int64, kind, stepName string) error {
	if seq <= 0 {
		return nil // pre-ordinal binaries retain their legacy name-keyed behavior
	}
	recorded, err := d.sup.Journal.FindRecordedCallBySeq(ctx, d.sup.RunID, seq)
	switch {
	case errors.Is(err, journal.ErrNotFound):
		return nil
	case errors.Is(err, journal.ErrRecordedCallConflict):
		return fmt.Errorf("%w: call ordinal %d has conflicting durable checkpoints", ErrReplayDivergence, seq)
	case err != nil:
		return fmt.Errorf("supervisor: lookup recorded call by seq: %w", err)
	case recorded.Kind != kind || recorded.StepName != stepName:
		return fmt.Errorf("%w: call ordinal %d was recorded as %s %q but this run reached it as %s %q (workflow source changed across a resume)",
			ErrReplayDivergence, seq, recorded.Kind, recorded.StepName, kind, stepName)
	default:
		return nil
	}
}

// A cached StepStart has no journal mutation that would otherwise check the
// distributed lease. Recheck every reply immediately before the child may
// continue, including replayed outputs and grants to execute a closure.
func (d *dispatcher) writeStepReply(ctx context.Context, replyTo int64, body wire.StepReply) error {
	if d.sup.LeaseOwner != "" && d.sup.Mode != "replay" {
		if err := d.sup.Journal.VerifyLeaseOwner(ctx, d.sup.RunID, d.sup.LeaseOwner); err != nil {
			return fmt.Errorf("supervisor: step reply lease fence: %w", err)
		}
	}
	reply, err := wire.Wrap(d.nextID(), replyTo, wire.KindStepReply, body)
	if err != nil {
		return err
	}
	return d.write(reply)
}

func (d *dispatcher) handleStepStart(ctx context.Context, f wire.Frame) error {
	var body wire.StepStart
	if err := wire.Unwrap(f, &body); err != nil {
		return err
	}

	// Ordinal path. body.Seq is the workflow's 1-based Step call ordinal, so
	// two iterations of one flow.Step(name) in a loop are distinct rows rather
	// than resolving to the same cached output. Zero means the workflow binary
	// predates the ordinal, which falls through to the legacy name-keyed lookup
	// below so already-compiled customer workflows keep running unchanged.
	if body.Seq > 0 {
		if err := d.verifyRecordedCall(ctx, body.Seq, journal.RecordedCallStep, body.StepName); err != nil {
			return err
		}
		cached, recorded, recordedIdempotencyKey, recordedInputHash, serr := d.sup.Journal.FindCachedOutputBySeqForInput(ctx, d.sup.RunID, body.Seq)
		switch {
		case serr == nil && recorded != body.StepName:
			// The ordinal was recorded against a DIFFERENT step, so the
			// workflow's program order changed between the original run and
			// this one (a step inserted, removed or reordered). Serving the
			// cache would attribute one step's result to another; re-executing
			// would repeat a side effect the journal says already happened.
			// Fail loudly instead. This check runs in LIVE mode too, not only
			// under `reactor replay`: the live suspend/resume path is exactly
			// where a redeploy mid-sleep changes the code underneath a run.
			return fmt.Errorf("%w: step ordinal %d was recorded as %q but this run reached it as %q (workflow source changed across a resume)",
				ErrReplayDivergence, body.Seq, recorded, body.StepName)
		case serr == nil:
			// The ordinal alone identifies a call position, not the operation
			// performed there. Keep the cache bound to the same idempotency key
			// and input hash as the frame that is asking for it. If either side
			// carries an identity field, an empty value on the other side is
			// still a change; only old rows/frames where both values are absent
			// retain the legacy ordinal replay behavior.
			if (body.IdempotencyKey != "" || recordedIdempotencyKey != "") && body.IdempotencyKey != recordedIdempotencyKey {
				return fmt.Errorf("%w: step ordinal %d idempotency key changed across a resume", ErrReplayDivergence, body.Seq)
			}
			if (body.InputHash != "" || recordedInputHash != "") && body.InputHash != recordedInputHash {
				return fmt.Errorf("%w: step ordinal %d input hash changed across a resume", ErrReplayDivergence, body.Seq)
			}
			return d.writeStepReply(ctx, f.ID, wire.StepReply{Replay: true, Output: cached})
		case !errors.Is(serr, journal.ErrNotFound):
			return fmt.Errorf("supervisor: journal lookup by seq: %w", serr)
		}
		// Not cached: fall through to the replay-mode gate + insert below.
		if d.sup.Mode == "replay" {
			return fmt.Errorf("%w: step %q (ordinal %d) has no cached output", ErrReplayDivergence, body.StepName, body.Seq)
		}
		if body.DurableAttempts {
			return d.handleDurableStepStart(ctx, f, body)
		}
		var startErr error
		if d.sup.LeaseOwner != "" {
			_, startErr = d.sup.Journal.RecordOwnedStepStartSeq(ctx, d.sup.RunID, d.sup.LeaseOwner, body.StepName, body.Seq, body.Attempt, body.IdempotencyKey, body.InputHash)
		} else {
			_, startErr = d.sup.Journal.RecordStepStartSeq(ctx, d.sup.RunID, body.StepName, body.Seq, body.Attempt, body.IdempotencyKey, body.InputHash)
		}
		if err := startErr; err != nil {
			return fmt.Errorf("supervisor: record step_start: %w", err)
		}
		return d.writeStepReply(ctx, f.ID, wire.StepReply{Replay: false})
	}

	cached, err := d.sup.Journal.FindCachedOutputForInput(ctx, d.sup.RunID, body.StepName, body.IdempotencyKey, body.InputHash)
	if err == nil {
		// Already succeeded against this exact input; tell the workflow
		// to use the cache. Input drift (workflow author changed the
		// Step input shape) falls through to the not-found branch and
		// triggers re-execution in live mode or divergence in replay.
		return d.writeStepReply(ctx, f.ID, wire.StepReply{Replay: true, Output: cached})
	}
	if !errors.Is(err, journal.ErrNotFound) {
		return fmt.Errorf("supervisor: journal lookup: %w", err)
	}

	// Replay mode forbids running new step closures. The operator invoked
	// `reactor replay <run-id>` against a historical run; if a step has
	// no cached output (for this exact input_hash) it means the workflow
	// source has diverged from the recorded DAG, so we abort cleanly
	// rather than re-execute side effects. Distinguish input-drift
	// (a cache row exists for this step under a different input) from
	// fully-missing-step so the diagnostic is actionable.
	if d.sup.Mode == "replay" {
		anyExists, probeErr := d.sup.Journal.HasCachedOutputAnyInput(ctx, d.sup.RunID, body.StepName)
		if probeErr == nil && anyExists {
			return fmt.Errorf("%w: step %q input drifted (input_hash mismatch with recorded run)", ErrReplayDivergence, body.StepName)
		}
		return fmt.Errorf("%w: step %q has no cached output", ErrReplayDivergence, body.StepName)
	}
	if body.DurableAttempts {
		return d.handleDurableStepStart(ctx, f, body)
	}

	// Insert a running attempt row. Best-effort: if the row already exists
	// (concurrent supervisor for the same run, which should never happen
	// thanks to leases), the journal returns inserted=false and we still
	// reply proceed; the second step_end will overwrite the first.
	var startErr error
	if d.sup.LeaseOwner != "" {
		_, startErr = d.sup.Journal.RecordOwnedStepStartSeq(ctx, d.sup.RunID, d.sup.LeaseOwner, body.StepName, 0, body.Attempt, body.IdempotencyKey, body.InputHash)
	} else {
		_, startErr = d.sup.Journal.RecordStepStart(ctx, d.sup.RunID, body.StepName, body.Attempt, body.IdempotencyKey, body.InputHash)
	}
	if err := startErr; err != nil {
		return fmt.Errorf("supervisor: record step_start: %w", err)
	}
	return d.writeStepReply(ctx, f.ID, wire.StepReply{Replay: false})
}

// handleDurableStepStart makes the journal, rather than a freshly spawned
// workflow process, authoritative for attempt numbering. ClaimStepAttemptSeq
// persists step_start before this method replies, so a worker crash consumes
// that number and a reaped run cannot reset its budget to attempt one.
func (d *dispatcher) handleDurableStepStart(ctx context.Context, f wire.Frame, body wire.StepStart) error {
	if body.MaxAttempts < 0 {
		return errors.New("supervisor: negative durable retry budget")
	}
	var (
		claim journal.StepAttemptClaim
		err   error
	)
	if d.sup.LeaseOwner != "" {
		claim, err = d.sup.Journal.ClaimOwnedStepAttemptSeq(ctx, d.sup.RunID, d.sup.LeaseOwner,
			body.StepName, body.Seq, body.MaxAttempts, body.IdempotencyKey, body.InputHash)
	} else {
		claim, err = d.sup.Journal.ClaimStepAttemptSeq(ctx, d.sup.RunID,
			body.StepName, body.Seq, body.MaxAttempts, body.IdempotencyKey, body.InputHash)
	}
	if err != nil {
		if errors.Is(err, journal.ErrStepAttemptDivergence) {
			return fmt.Errorf("%w: step %q (ordinal %d) changed while retrying", ErrReplayDivergence, body.StepName, body.Seq)
		}
		return fmt.Errorf("supervisor: claim durable step attempt: %w", err)
	}
	if claim.RetryWait > 0 {
		waitMs := int64((claim.RetryWait + time.Millisecond - 1) / time.Millisecond)
		return d.writeStepReply(ctx, f.ID, wire.StepReply{RetryWaitMs: waitMs})
	}

	if !claim.Exhausted {
		return d.writeStepReply(ctx, f.ID, wire.StepReply{
			Replay:        false,
			Attempt:       claim.Attempt,
			BudgetAttempt: claim.BudgetAttempt,
		})
	}

	// The no-closure verdict is itself durable. If the last allocated attempt
	// died while running, terminalize that same row; if step_end had already
	// persisted StatusFailed, preserve its original error. Either path lands in
	// DLQ before the SDK is told the budget is exhausted. A crash between the
	// step row UPDATE and the original DLQ write is therefore repaired here.
	if claim.Previous == nil {
		return errors.New("supervisor: retry budget exhausted without a prior attempt")
	}
	state := *claim.Previous
	if state.Status == journal.StatusSucceeded {
		// Defensive race handling: the normal cache lookup above should win,
		// but serving the committed result is safer than dead-lettering it.
		return d.writeStepReply(ctx, f.ID, wire.StepReply{Replay: true, Output: state.Output})
	}
	if state.Status == journal.StatusRunning || state.Status == journal.StatusRetrying {
		if state.Status == journal.StatusRunning {
			state.ErrorText = fmt.Sprintf("retry budget exhausted after interrupted attempt %d", state.Attempt)
		} else if state.ErrorText == "" {
			state.ErrorText = fmt.Sprintf("retry budget exhausted after retryable attempt %d", state.Attempt)
		} else {
			state.ErrorText = fmt.Sprintf("retry budget exhausted after attempt %d: %s", state.Attempt, state.ErrorText)
		}
		state.Output = json.RawMessage("null")
		var finalizeErr error
		if d.sup.LeaseOwner != "" {
			finalizeErr = d.sup.Journal.FinalizeOwnedExhaustedStepAttemptSeq(ctx, d.sup.RunID,
				d.sup.LeaseOwner, body.StepName, body.Seq, state.Attempt, state.Output, state.ErrorText)
		} else {
			finalizeErr = d.sup.Journal.FinalizeExhaustedStepAttemptSeq(ctx, d.sup.RunID,
				body.StepName, body.Seq, state.Attempt, state.Output, state.ErrorText)
		}
		if err := finalizeErr; err != nil {
			return fmt.Errorf("supervisor: terminalize exhausted step attempt: %w", err)
		}
		d.deadLetter.Store(true)
		state.Status = journal.StatusFailed
	}
	if state.ErrorText == "" {
		state.ErrorText = fmt.Sprintf("retry budget exhausted after attempt %d", state.Attempt)
	}
	payload := state.Output
	if len(payload) == 0 || string(payload) == "null" {
		payload = json.RawMessage("{}")
	}
	var repairErr error
	if d.sup.LeaseOwner != "" {
		_, repairErr = d.sup.Journal.EnsureOwnedStepAttemptDeadLetter(ctx, d.sup.RunID,
			d.sup.LeaseOwner, body.StepName, body.Seq, state.Attempt, state.ErrorText, payload)
	} else {
		_, repairErr = d.sup.Journal.EnsureStepAttemptDeadLetter(ctx, d.sup.RunID,
			body.StepName, body.Seq, state.Attempt, state.ErrorText, payload)
	}
	if err := repairErr; err != nil {
		// Do not send RetryExhausted when the operator-visible terminal record
		// is missing. Returning a protocol error keeps the run recoverable: a
		// restarted/reaped supervisor retries this idempotent repair first.
		return errors.Join(ErrDeadLetterRepairRecoverable,
			fmt.Errorf("supervisor: repair exhausted step dead-letter: %w", err))
	}
	d.deadLetter.Store(true)
	return d.writeStepReply(ctx, f.ID, wire.StepReply{
		Replay:         false,
		Attempt:        state.Attempt,
		BudgetAttempt:  claim.BudgetAttempt,
		RetryExhausted: true,
	})
}

// ErrReplayDivergence signals that a replay run hit a step with no cached
// output. The operator's workflow source has changed since the recorded
// run; replay can't proceed without re-executing side effects.
var ErrReplayDivergence = errors.New("supervisor: replay divergence")

func (d *dispatcher) handleStepEnd(ctx context.Context, f wire.Frame) error {
	if d.sup.Mode == "replay" {
		// Replay may return already-recorded Step outputs, but it must never
		// accept a child-supplied outcome that changes historical attempts.
		return errors.New("supervisor: step_end cannot write during replay")
	}
	var body wire.StepEnd
	if err := wire.Unwrap(f, &body); err != nil {
		return err
	}
	if body.RetryAfterMs < 0 || body.RetryAfterMs > 30000 ||
		(body.RetryAfterMs > 0 && (!body.DurableAttempts || !body.Retryable || body.ErrorText == "")) {
		return errors.New("supervisor: invalid provider retry delay")
	}
	out := body.Output
	if len(out) == 0 {
		out = json.RawMessage("null")
	}
	var recordErr error
	if body.DurableAttempts || (body.ErrorText != "" && !body.Retryable) {
		var deadLettered bool
		if d.sup.LeaseOwner != "" {
			deadLettered, recordErr = d.sup.Journal.FinalizeOwnedStepAttemptSeqWithRetryAfter(ctx, d.sup.RunID, d.sup.LeaseOwner, body.StepName, body.Seq, body.Attempt, out, body.ErrorText, body.Retryable, time.Duration(body.RetryAfterMs)*time.Millisecond)
		} else {
			deadLettered, recordErr = d.sup.Journal.FinalizeStepAttemptSeqWithRetryAfter(ctx, d.sup.RunID, body.StepName, body.Seq, body.Attempt, out, body.ErrorText, body.Retryable, time.Duration(body.RetryAfterMs)*time.Millisecond)
		}
		if deadLettered {
			d.deadLetter.Store(true)
		}
	} else {
		if d.sup.LeaseOwner != "" {
			recordErr = d.sup.Journal.RecordOwnedStepEndSeq(ctx, d.sup.RunID, d.sup.LeaseOwner, body.StepName, body.Seq, body.Attempt, out, body.ErrorText)
		} else {
			recordErr = d.sup.Journal.RecordStepEndSeq(ctx, d.sup.RunID, body.StepName, body.Seq, body.Attempt, out, body.ErrorText)
		}
	}
	if recordErr != nil {
		return fmt.Errorf("supervisor: record step_end: %w", recordErr)
	}
	// Final-attempt failures land in the dead-letter queue so an operator
	// can inspect or replay them without grovelling through the steps
	// table. Retryable errors are kept out of DLQ; the workflow side will
	// emit another step_start with a higher attempt number for them.
	// Terminal outcomes, including legacy/non-durable wire frames, use the
	// atomic finalizer above. That preserves body.Seq/body.Attempt as exact DLQ
	// identity and never ACKs a failed step whose operator record did not commit.
	ack, _ := wire.Wrap(d.nextID(), f.ID, wire.KindAck, nil)
	return d.write(ack)
}

// maxScheduleHorizon bounds how far into the future a workflow may push a
// schedules.wake_at. Both wire.Sleep.UntilUnix and wire.AwaitSignal.TimeoutMs
// are workflow-author controlled, and an out-of-range value formats to a
// wake_at like "146138514283-06-19T..." which, stored as TEXT, sorts BEFORE
// every real timestamp AND still satisfies the "wake_at <= now" predicate.
// FindDueSchedules would then hit that row first on every tick and fail, so a
// single poisoned row stops every suspended run in every tenant from ever
// resuming. Ten years is far past any legitimate durable sleep.
const maxScheduleHorizon = 10 * 365 * 24 * time.Hour

func (d *dispatcher) handleSleep(ctx context.Context, f wire.Frame) error {
	var body wire.Sleep
	if err := wire.Unwrap(f, &body); err != nil {
		return err
	}
	if err := d.verifyRecordedCall(ctx, body.Seq, journal.KindSleep, body.StepName); err != nil {
		return err
	}

	// Resume path: if a previous suspend wrote a sleep schedule for this
	// (run_id, step_name), pin to its wake_at instead of the freshly-
	// recomputed UntilUnix. The SDK can't help here because time.Now() in
	// the workflow body advances across the suspend/respawn boundary, so
	// the second-spawn UntilUnix is always now+d which would re-suspend
	// forever. The journal row is the source of truth for wake_at.
	// Resolve by call ordinal when the workflow binary supplies one, so a Sleep
	// inside a loop looks up ITS iteration rather than the first iteration's
	// row (whose wake_at is already past, which made every later iteration ack
	// instantly and collapsed a per-item delay into a single sleep).
	existing, err := d.findSleepSchedule(ctx, body)
	switch {
	case err == nil:
		// A schedule is keyed by the per-run ordinal, but the ordinal alone
		// does not prove that the resumed source still performs the same
		// operation at that position. If a workflow was rebuilt with a
		// different Sleep name, reusing the old checkpoint would silently
		// acknowledge the wrong wait and let the run continue out of order.
		// Keep this guard on the live resume path as well as replay mode.
		if existing.StepName != body.StepName {
			return fmt.Errorf("%w: sleep ordinal %d was recorded as %q but this run reached it as %q (workflow source changed across a resume)",
				ErrReplayDivergence, body.Seq, existing.StepName, body.StepName)
		}
		if !existing.WakeAt.After(d.sup.Now()) {
			// A lease/startup recovery can reach this row without the scheduler
			// having claimed it (crash after INSERT, before suspended status).
			// Retire the exact checkpoint before ACK so it cannot later wake an
			// unrelated second wait on the same run.
			if d.sup.Mode != "replay" {
				if err := d.sup.Journal.FireSchedule(ctx, existing.ID); err != nil {
					return fmt.Errorf("supervisor: retire resumed sleep schedule: %w", err)
				}
			}
			ack, _ := wire.Wrap(d.nextID(), f.ID, wire.KindAck, nil)
			return d.write(ack)
		}
		// Schedule exists but wake_at is still in the future (rare: a
		// replay happened before wake). Re-suspend on the existing
		// wake_at so the scheduler tick handles the rest.
		return d.suspendForSleep(ctx, body.StepName, body.Seq, existing.WakeAt, false)
	case errors.Is(err, journal.ErrNotFound):
		if d.sup.Mode == "replay" {
			return fmt.Errorf("%w: sleep %q has no recorded schedule", ErrReplayDivergence, body.StepName)
		}
		// Fresh path; fall through.
	default:
		return fmt.Errorf("supervisor: lookup sleep schedule: %w", err)
	}

	now := d.sup.Now()
	until := time.Unix(body.UntilUnix, 0)
	if maxWake := now.Add(maxScheduleHorizon); until.After(maxWake) {
		d.sup.Log.Warn("supervisor: sleep wake time exceeds the max horizon; clamping",
			"run_id", d.sup.RunID, "step", body.StepName,
			"requested_unix", body.UntilUnix,
			"clamped_to", maxWake.UTC().Format(time.RFC3339))
		until = maxWake
	}
	wait := until.Sub(now)

	// Already past wake on the first call: the workflow body computed an
	// UntilUnix in the past (e.g. negative duration). Ack immediately.
	if wait <= 0 {
		ack, _ := wire.Wrap(d.nextID(), f.ID, wire.KindAck, nil)
		return d.write(ack)
	}

	// Short sleep: block in place. The supervisor's lifetime is bounded
	// by SuspendThreshold so this can't pin a goroutine for days.
	if wait <= d.sup.SuspendThreshold {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		ack, _ := wire.Wrap(d.nextID(), f.ID, wire.KindAck, nil)
		return d.write(ack)
	}

	// Long sleep: write a schedules row pinned to the first-call until,
	// then suspend. Subsequent respawns enter the resume branch above.
	return d.suspendForSleep(ctx, body.StepName, body.Seq, until, true)
}

// suspendForSleep is the shared tail of the fresh + resume long-sleep
// paths. It writes (or relies on an existing) schedules row, marks the
// run suspended, sends Cancel so the workflow process exits cleanly,
// and returns errSuspended so the dispatcher loop unwinds.
// findSleepSchedule prefers the call-ordinal lookup and falls back to the legacy
// name-keyed one for workflow binaries built before the ordinal existed.
func (d *dispatcher) findSleepSchedule(ctx context.Context, body wire.Sleep) (journal.Schedule, error) {
	if body.Seq > 0 {
		return d.sup.Journal.FindScheduleBySeq(ctx, d.sup.RunID, body.Seq, journal.KindSleep)
	}
	return d.sup.Journal.FindLatestSleepSchedule(ctx, d.sup.RunID, body.StepName)
}

// findSignalSchedule mirrors findSleepSchedule for awaits.
func (d *dispatcher) findSignalSchedule(ctx context.Context, body wire.AwaitSignal) (journal.Schedule, error) {
	if body.Seq > 0 {
		return d.sup.Journal.FindScheduleBySeq(ctx, d.sup.RunID, body.Seq, journal.KindSignal)
	}
	return d.sup.Journal.FindLatestSignalSchedule(ctx, d.sup.RunID, body.StepName)
}

func (d *dispatcher) suspendForSleep(ctx context.Context, stepName string, seq int64, wakeAt time.Time, writeRow bool) error {
	if writeRow {
		if _, err := d.sup.Journal.ScheduleSleepSeq(ctx, d.sup.RunID, stepName, seq, wakeAt); err != nil {
			return fmt.Errorf("supervisor: schedule sleep: %w", err)
		}
	}
	d.suspended.Store(true)
	cancel, _ := wire.Wrap(d.nextID(), 0, wire.KindCancel, wire.Cancel{
		Reason: fmt.Sprintf("suspend until %s for step %q", wakeAt.Format(time.RFC3339), stepName),
	})
	if err := d.write(cancel); err != nil {
		return err
	}
	// Returning io.EOF here would conflate with pipe closure; use a
	// sentinel that the loop translates to a clean exit.
	return errSuspended
}

// errSuspended is the sentinel that handleSleep returns when it has
// upgraded a long Sleep to a suspend. The dispatcher loop unwinds, the
// supervisor closes stdin, the workflow process notices Cancel + EOF and
// exits 0.
var errSuspended = errors.New("supervisor: workflow suspended on long sleep")

// handleAwaitSignal persists or resumes a signal-await schedule.
//
// Fresh path: workflow's first call. The supervisor derives a deterministic
// token from (run_id, signal_name), writes a schedules row keyed by that
// token, asks the workflow process to exit, and lets the scheduler tick
// re-spawn the run when either the external HTTP delivery or the timeout
// expiry fires.
//
// Resume path: workflow re-runs Run() after a scheduler resume. The
// supervisor finds the existing schedule for (run_id, step_name); if a
// payload was delivered, it replies SignalDeliver{Payload} so the SDK
// returns the value. If wake_at has elapsed without a payload, it replies
// SignalDeliver{Expired:true} so AwaitSignal returns context.DeadlineExceeded.
func (d *dispatcher) handleAwaitSignal(ctx context.Context, f wire.Frame) error {
	var body wire.AwaitSignal
	if err := wire.Unwrap(f, &body); err != nil {
		return err
	}
	if err := d.verifyRecordedCall(ctx, body.Seq, journal.KindSignal, body.StepName); err != nil {
		return err
	}

	// Resolve by call ordinal when available. Two AwaitSignal calls sharing a
	// signal name previously collapsed onto one row, so the second was served
	// the first's already-delivered payload and never suspended: an
	// approve-then-confirm gate auto-confirmed itself from one approval.
	existing, err := d.findSignalSchedule(ctx, body)
	switch {
	case err == nil:
		// The call ordinal identifies the position in the workflow, while the
		// names identify the operation and public capability that were recorded
		// there. A source change at the same ordinal must fail closed rather
		// than deliver a prior signal payload to a different await.
		if existing.StepName != body.StepName || existing.SignalName != body.SignalName {
			return fmt.Errorf("%w: signal ordinal %d was recorded as step %q/signal %q but this run reached step %q/signal %q (workflow source changed across a resume)",
				ErrReplayDivergence, body.Seq, existing.StepName, existing.SignalName, body.StepName, body.SignalName)
		}
		// Resume path. Decide based on payload presence and wake_at.
		if len(existing.SignalPayload) > 0 {
			if d.sup.Mode != "replay" {
				if err := d.sup.Journal.FireSchedule(ctx, existing.ID); err != nil {
					return fmt.Errorf("supervisor: retire delivered signal schedule: %w", err)
				}
			}
			reply, wrapErr := wire.Wrap(d.nextID(), f.ID, wire.KindSignalDeliver, wire.SignalDeliver{
				SignalName: existing.SignalName,
				Token:      existing.SignalToken,
				Payload:    json.RawMessage(existing.SignalPayload),
			})
			if wrapErr != nil {
				// A legacy/imported schedule may contain malformed or
				// oversized bytes even though public ingress rejects them.
				// Never send the zero Frame produced by ignoring Wrap's
				// error: the child would wait for a reply and hide the
				// durable data-integrity failure as a protocol hang.
				return fmt.Errorf("supervisor: encode delivered signal frame: %w", wrapErr)
			}
			return d.write(reply)
		}
		if !existing.WakeAt.IsZero() && !existing.WakeAt.After(d.sup.Now()) {
			if d.sup.Mode != "replay" {
				if err := d.sup.Journal.FireSchedule(ctx, existing.ID); err != nil {
					return fmt.Errorf("supervisor: retire expired signal schedule: %w", err)
				}
			}
			reply, wrapErr := wire.Wrap(d.nextID(), f.ID, wire.KindSignalDeliver, wire.SignalDeliver{
				SignalName: existing.SignalName,
				Token:      existing.SignalToken,
				Expired:    true,
			})
			if wrapErr != nil {
				return fmt.Errorf("supervisor: encode expired signal frame: %w", wrapErr)
			}
			return d.write(reply)
		}
		// Schedule exists but neither delivered nor expired (race: replay
		// happened between schedule creation and timeout). Re-suspend on
		// the same token so external deliveries against it still resolve.
		return d.suspendForSignal(body)
	case errors.Is(err, journal.ErrNotFound):
		if d.sup.Mode == "replay" {
			return fmt.Errorf("%w: signal %q has no recorded schedule", ErrReplayDivergence, body.SignalName)
		}
		// Fresh path.
	default:
		return fmt.Errorf("supervisor: lookup signal schedule: %w", err)
	}

	timeout := time.Duration(body.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 365 * 24 * time.Hour
	}
	if timeout > maxScheduleHorizon {
		// Same poison-row hazard as handleSleep: TimeoutMs is
		// workflow-author controlled and lands in schedules.wake_at.
		d.sup.Log.Warn("supervisor: signal timeout exceeds the max horizon; clamping",
			"run_id", d.sup.RunID, "step", body.StepName, "requested_ms", body.TimeoutMs)
		timeout = maxScheduleHorizon
	}
	expiresAt := d.sup.Now().Add(timeout)
	token := DeriveSignalToken(perRunSignalKey(d.sup.SignalSigningKey, d.sup.RunID), d.sup.RunID, body.SignalName)
	if _, err := d.sup.Journal.ScheduleSignalSeq(ctx, d.sup.RunID, body.StepName, body.Seq, body.SignalName, token, expiresAt); err != nil {
		return fmt.Errorf("supervisor: schedule signal: %w", err)
	}
	// Log only the token fingerprint (first 8 chars). The full token is a
	// capability that grants the holder POST /signal/{token} access
	// without HMAC; anyone reading the log otherwise can resume any
	// suspended workflow with attacker-controlled payload.
	d.sup.Log.Info("signal registered",
		"run_id", d.sup.RunID, "step", body.StepName, "signal", body.SignalName,
		"token_fp", tokenFingerprint(token), "expires_at", expiresAt.UTC().Format(time.RFC3339))
	return d.suspendForSignal(body)
}

// suspendForSignal sends Cancel to the workflow process, marks the run
// suspended, and returns errSuspended so the dispatcher loop unwinds.
func (d *dispatcher) suspendForSignal(body wire.AwaitSignal) error {
	d.suspended.Store(true)
	cancel, _ := wire.Wrap(d.nextID(), 0, wire.KindCancel, wire.Cancel{
		Reason: fmt.Sprintf("awaiting signal %q", body.SignalName),
	})
	if err := d.write(cancel); err != nil {
		return err
	}
	return errSuspended
}

// tokenFingerprint returns a short, non-reversible identifier for a
// capability token so it can be logged for correlation without leaking
// the token itself. 8 hex chars is enough to ground a log search; the
// full token stays in the workflow's private context and the encrypted
// schedule envelope.
func tokenFingerprint(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}

// signalKeyPurpose domain-separates the per-run signal signing key derivation
// from any other use of the master key.
const signalKeyPurpose = "reactor-signal-v1:"

// perRunSignalKey derives the per-run signing key (hex) from the root signing
// key (the vault master key) and the runID: HMAC(master, "reactor-signal-v1:"+
// runID). It is stable across suspend/resume (master + runID are stable) and is
// delivered to the workflow over the private Hello frame so the SDK computes
// the same token. Returns "" when no signing key is wired (legacy/test paths),
// which selects the legacy runID-only derivation on both sides.
func perRunSignalKey(signingKey []byte, runID string) string {
	if len(signingKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(signalKeyPurpose + runID))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeriveSignalToken produces the capability token for a signal-await. Both the
// supervisor and the SDK compute the same value so workflow code can embed the
// public delivery URL (POST /signal/{token}) in user-facing content (approval
// emails, Slack DMs) before the run suspends.
//
// When perRunKeyHex is set, the token is HMAC(perRunKey, signalName): the
// per-run key is a secret derived from the master key and shared with the
// workflow only over the private Hello frame, so a party who knows only the
// (semi-public, log/URL-exposed) runID CANNOT forge the token. When it is empty
// (no signing key wired), it falls back to the legacy runID-only SHA-256; this
// keeps signal-less test paths working but is NOT unforgeable, so production
// always wires SignalSigningKey. signalName namespaces multiple awaits per run.
func DeriveSignalToken(perRunKeyHex, runID, signalName string) string {
	if perRunKeyHex != "" {
		key, err := hex.DecodeString(perRunKeyHex)
		if err == nil && len(key) > 0 {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(signalName))
			return "sig_" + hex.EncodeToString(mac.Sum(nil)[:16])
		}
	}
	h := sha256.Sum256([]byte(runID + ":signal:" + signalName))
	return "sig_" + hex.EncodeToString(h[:16])
}

// oauthTenant resolves the run's tenant (to scope an oauth: connection lookup).
// Returns "" when it can't be established, which the caller treats as deny.
func (d *dispatcher) oauthTenant(ctx context.Context) string {
	_, tenant, ok := d.runIdentity(ctx)
	if !ok {
		return ""
	}
	return tenant
}

// runIdentity resolves which workflow this run IS, and whose it is, from the run
// id. Returns ok=false when it cannot be established, and every caller treats
// that as deny.
//
// This replaced resolving identity from d.sup.WorkflowSlug via the UNSCOPED
// WorkflowIDBySlug. Slugs are unique only PER TENANT, so once two tenants owned
// the same slug that lookup ("WHERE slug = $1 ORDER BY created_at DESC LIMIT 1")
// returned whichever tenant registered it most recently, no matter who was
// actually executing. The secret ACL was then evaluated against the wrong
// workflow, so a victim's grant authorised an attacker's run and the plaintext
// came back; the oauth branch picked the wrong tenant's connections the same way.
// A run id is unambiguous, and runs.workflow_id is written at enqueue time.
func (d *dispatcher) runIdentity(ctx context.Context) (workflowID, tenantID string, ok bool) {
	if d.sup.Journal == nil || d.sup.RunID == "" {
		return "", "", false
	}
	wfID, tenant, err := d.sup.Journal.RunIdentity(ctx, d.sup.RunID)
	if err != nil || wfID == "" {
		return "", "", false
	}
	return wfID, tenant, true
}

func (d *dispatcher) handleSecretFetch(ctx context.Context, f wire.Frame) error {
	var body wire.SecretFetch
	if err := wire.Unwrap(f, &body); err != nil {
		return err
	}
	// Review runs and historical replay must never resolve live credentials.
	// Only a live execution may turn an opaque credential ID into value bytes.
	// An unknown mode also fails closed rather than inheriting live behavior.
	if d.sup.Mode != "live" {
		deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
		return d.write(deny)
	}

	// Per-workflow secret ACL gate. Resolve workflow_id once + check
	// against workflow_secret_grants. ErrACLEmpty means the table has
	// no rows and denies unless the explicit legacy permissive mode is
	// enabled. Any other error from the
	// grant probe is logged + treated as deny so a misbehaving DB
	// doesn't accidentally hand out credentials.
	//
	// An empty WorkflowSlug or a run we cannot resolve into a workflow_id is
	// always denied rather than bypassed: a missing identity means we cannot
	// establish either the grant decision or the tenant boundary. This remains
	// true in the explicit legacy permissive mode; that flag only relaxes the
	// empty-ACL grant requirement, never tenant isolation.
	// Identity comes from the RUN, never from the slug. See runIdentity: the
	// slug-based lookup crossed tenant boundaries once two tenants could own one
	// slug, which turned the victim's grant into the attacker's authorisation.
	runWfID, runTenant, identityOK := d.runIdentity(ctx)
	if !identityOK {
		d.sup.Log.Warn("supervisor: secret access denied (cannot establish which workflow this run is; no tenant or grant decision is possible)",
			"run", d.sup.RunID, "workflow", d.sup.WorkflowSlug, "credential_id", body.ID)
		deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
		return d.write(deny)
	}
	// Defence in depth behind the grant check. GrantSecret refuses
	// cross-tenant grants, but a row written before that guard existed would
	// still authorise, and Vault.Get has no tenant predicate of its own. Keep
	// this check outside the strict/permissive branch: permissive mode is an
	// explicit legacy escape hatch for an empty ACL, not a cross-tenant escape
	// hatch. SecretTenant also handles oauth:<connection-id>, which lives in a
	// different table from regular credentials.
	if credTenant, cErr := d.sup.Journal.SecretTenant(ctx, body.ID); cErr != nil || credTenant != runTenant {
		d.sup.Log.Warn("supervisor: secret access denied (credential belongs to another tenant or cannot be resolved)",
			"run_tenant", runTenant, "credential_id", body.ID, "err", cErr)
		deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
		return d.write(deny)
	}

	legacyEmptyACL := false
	if !d.sup.ACLPermissive {
		wfID := runWfID
		ok, err := d.sup.Journal.HasGrant(ctx, wfID, body.ID)
		switch {
		case errors.Is(err, journal.ErrACLEmpty):
			// Fail CLOSED on an empty table. Do NOT steer the operator toward
			// REACTOR_VAULT_ACL_PERMISSIVE=1 (that opens the vault to every
			// workflow); the secure fix is to seed the one grant this workflow
			// needs.
			d.sup.Log.Warn("supervisor: secret access denied (no secret grants configured; grant this workflow the credential with `reactor vault grant <workflow> <credential>`)",
				"workflow", d.sup.WorkflowSlug, "credential_id", body.ID)
			deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
			return d.write(deny)
		case err != nil:
			d.sup.Log.Warn("supervisor: grant check failed; denying",
				"err", err, "workflow", d.sup.WorkflowSlug, "credential_id", body.ID)
			deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
			return d.write(deny)
		case !ok:
			d.sup.Log.Warn("supervisor: secret access denied (no grant)",
				"workflow", d.sup.WorkflowSlug, "credential_id", body.ID)
			deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
			return d.write(deny)
		}
	} else {
		// Permissive mode still emits an audit gate when the run resolves: the
		// path mirrors the strict branch but skips the deny on ACLEmpty so legacy
		// zero-grant installs continue to function. It uses the same run-derived
		// workflow id, so permissive does not mean "resolve across tenants".
		{
			wfID := runWfID
			ok, gErr := d.sup.Journal.HasGrant(ctx, wfID, body.ID)
			switch {
			case errors.Is(gErr, journal.ErrACLEmpty):
				// Permissive + empty table = every workflow can read every
				// credential. This is the documented v0 escape hatch, but it is
				// NOT silent: warn loudly on each allow so a permissive install
				// with no grants is visible in the logs, not a quiet open door.
				d.sup.Log.Warn("supervisor: SECRET ACL WIDE OPEN within this tenant (REACTOR_VAULT_ACL_PERMISSIVE=1 and no grants seeded); this workflow was allowed a credential with no grant. Seed grants and unset the permissive flag.",
					"workflow", d.sup.WorkflowSlug, "credential_id", body.ID)
				legacyEmptyACL = true
			case gErr == nil && !ok:
				d.sup.Log.Warn("supervisor: secret access denied (no grant) [permissive]",
					"workflow", d.sup.WorkflowSlug, "credential_id", body.ID)
				deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
				return d.write(deny)
			case gErr != nil:
				// Permissive mode only relaxes the empty-ACL migration fallback.
				// A real grant-probe failure must still fail closed; otherwise a
				// database outage (or a dropped grants table) falls through to
				// Vault.Get and discloses the credential to any workflow.
				d.sup.Log.Warn("supervisor: grant check failed; denying [permissive]",
					"err", gErr, "workflow", d.sup.WorkflowSlug, "credential_id", body.ID)
				deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
				return d.write(deny)
			}
		}
	}
	// Avoid resolving a plaintext credential or refreshing an OAuth token for
	// a worker that has already lost its run. The receipt transaction below
	// repeats this fence after resolution, before any value reaches the child.
	if err := d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, runWfID, runTenant, d.sup.LeaseOwner); err != nil {
		deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
		return d.write(deny)
	}
	// A resolved value cannot cross the child pipe without a durable receipt.
	// The receipt is bound to this exact run/workflow/tenant by the journal's
	// INSERT query. A failed write (including an absent migration or lost DB)
	// produces the same NotFound reply as a denied grant, with no value bytes.
	auditAndReply := func(kind string, value wire.SecretReply) error {
		if err := d.sup.Journal.AppendRuntimeSecretAccess(ctx, d.sup.LeaseOwner, journal.RuntimeSecretAccess{
			TenantID: runTenant, WorkflowID: runWfID, RunID: d.sup.RunID,
			SecretRef: body.ID, SecretKind: kind,
		}); err != nil {
			d.sup.Log.Error("supervisor: runtime secret audit unavailable; denying value release",
				"run_id", d.sup.RunID, "err", err)
			value = wire.SecretReply{NotFound: true}
		}
		// The lease can expire or cancellation can commit after the receipt.
		// A second read catches those changes when they precede this wire send.
		if err := d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, runWfID, runTenant, d.sup.LeaseOwner); err != nil {
			value = wire.SecretReply{NotFound: true}
		}
		// A grant can be revoked while a vault read or OAuth refresh is in
		// flight. The initial ACL decision is not authority to release the
		// resolved value after that revocation. Keep the explicit legacy
		// empty-ACL behavior, but fail closed on all other lookup failures.
		if !value.NotFound {
			granted, grantErr := d.sup.Journal.HasGrant(ctx, runWfID, body.ID)
			if !(grantErr == nil && granted) && !(legacyEmptyACL && errors.Is(grantErr, journal.ErrACLEmpty)) {
				value = wire.SecretReply{NotFound: true}
			}
		}
		if kind == "oauth" {
			// The operator may approve broker-only access while the audit
			// transaction runs. Recheck immediately before framing raw bytes.
			connectionID := strings.TrimPrefix(body.ID, journal.OAuthSecretPrefix)
			allowed, err := d.sup.OAuthTokens.RawTokenAllowed(ctx, connectionID, runTenant)
			if err != nil || !allowed {
				value = wire.SecretReply{NotFound: true}
			}
		}
		reply, err := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, value)
		if err != nil {
			return err
		}
		return d.write(reply)
	}

	// Legacy OAuth connection tokens: `oauth:<connection-id>` resolves to a
	// fresh access token (auto-refreshed), scoped to this run's tenant. This
	// route excludes Salesforce by provider ID and known OAuth endpoints,
	// including pre-existing provider aliases. Other providers' raw tokens are
	// sent to the workflow child after the grant, lease, and audit checks;
	// only Salesforce uses the host-owned GET connector broker today.
	if rest, isOAuth := strings.CutPrefix(body.ID, "oauth:"); isOAuth {
		if d.sup.OAuthTokens == nil {
			deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
			return d.write(deny)
		}
		tenantID := d.oauthTenant(ctx)
		if tenantID == "" {
			// Can't establish the run's tenant -> can't safely scope the
			// connection lookup; deny rather than resolve unscoped.
			d.sup.Log.Warn("supervisor: oauth denied (could not resolve run tenant)", "connection", rest)
			deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
			return d.write(deny)
		}
		allowed, perr := d.sup.OAuthTokens.RawTokenAllowed(ctx, rest, tenantID)
		if perr != nil || !allowed {
			// Salesforce OAuth tokens must stay on the host. Provider metadata
			// lookup failures also fail closed, without requesting token bytes.
			deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
			return d.write(deny)
		}
		tok, terr := d.sup.OAuthTokens.RawToken(ctx, rest, tenantID)
		if terr != nil || tok == "" {
			d.sup.Log.Warn("supervisor: oauth token resolution failed", "connection", rest, "err", terr)
			deny, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
			return d.write(deny)
		}
		return auditAndReply("oauth", wire.SecretReply{Value: []byte(tok)})
	}

	sec, err := d.sup.Vault.Get(ctx, body.ID)
	if err != nil {
		reply, _ := wire.Wrap(d.nextID(), f.ID, wire.KindSecretReply, wire.SecretReply{NotFound: true})
		return d.write(reply)
	}
	return auditAndReply("vault", wire.SecretReply{
		Value:       sec.Reveal(),
		Fingerprint: sec.Fingerprint(),
	})
}

func (d *dispatcher) handleLog(f wire.Frame) {
	var body wire.Log
	if err := wire.Unwrap(f, &body); err != nil {
		return
	}
	level := slog.LevelInfo
	switch body.Level {
	case "DEBUG", "debug":
		level = slog.LevelDebug
	case "WARN", "warn":
		level = slog.LevelWarn
	case "ERROR", "error":
		level = slog.LevelError
	}
	// A child controls both its message and attribute names. Keep those values
	// available in the tenant's local log, but never promote them to the host
	// record message or top-level operational attributes: the host handler may
	// ship warn/error records to the shared Flare store. In particular, a child
	// must not be able to spoof run_id or smuggle a secret under an allowlisted
	// field such as status.
	d.sup.Log.Log(context.Background(), level, "workflow log", "run_id", d.sup.RunID)
	if d.sup.LogSink != nil {
		// Render a flat single-line shape for the SSE tail. slog's text
		// handler shape is overkill for the dashboard; this stays
		// human-readable while round-tripping through SSE's data: lines.
		var rendered = body.Msg
		if len(body.Attrs) > 0 {
			rendered += renderAttrs(body.Attrs)
		}
		d.sup.LogSink(d.sup.RunID, "workflow: "+body.Level+" "+rendered)
	}
}

// renderAttrs flattens a workflow-emitted attrs map into a key=value
// suffix string. Order is map-iteration (non-deterministic) but for
// log-tail UX the legibility cost is acceptable + the lines are still
// the same in the slog handler which uses its own ordering.
func renderAttrs(attrs map[string]any) string {
	if len(attrs) == 0 {
		return ""
	}
	out := " ["
	first := true
	for k, v := range attrs {
		if !first {
			out += " "
		}
		first = false
		out += fmt.Sprintf("%s=%v", k, v)
	}
	out += "]"
	return out
}

// childEnvAllowlist is the set of environment variables a workflow
// subprocess is allowed to inherit from the daemon. Everything else (the
// vault master key, the DB URL, ANTHROPIC_API_KEY, any other REACTOR_*
// secret) is withheld; secrets reach the workflow only through the
// gated secret_fetch wire frame. SSL_CERT_* stay in so workflows making
// outbound HTTPS calls find the system CA bundle inside slim containers.
var childEnvAllowlist = map[string]struct{}{
	"PATH": {},
	"TZ":   {}, "LANG": {}, "LC_ALL": {}, "LC_CTYPE": {}, "LC_NUMERIC": {},
	"USER": {}, "LOGNAME": {}, "TERM": {},
	"SSL_CERT_FILE": {}, "SSL_CERT_DIR": {},
}

// childEnv builds the subprocess environment from the allowlist plus the
// trigger input and any test-injected ExtraEnv. Returning a fresh slice
// (never os.Environ()) is the security boundary that keeps the daemon's
// secrets out of untrusted workflow code.
func childEnv(input []byte, extra []string) []string {
	env := make([]string, 0, len(childEnvAllowlist)+len(extra)+1)
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		if _, ok := childEnvAllowlist[kv[:eq]]; ok {
			env = append(env, kv)
		}
	}
	if len(input) > 0 {
		env = append(env, "REACTOR_INPUT="+string(input))
	}
	for _, kv := range extra {
		eq := strings.IndexByte(kv, '=')
		key := kv
		if eq > 0 {
			key = kv[:eq]
		}
		// ExtraEnv exists only for tightly-controlled test instrumentation and
		// the daemon's dry-run marker. Keep that surface narrow: accepting an
		// arbitrary key here would let a future caller accidentally reintroduce
		// a process secret after the inherited environment allowlist removed it.
		if !strings.HasPrefix(key, "FF_TEST_") && key != "REACTOR_MODE" {
			continue
		}
		if strings.HasPrefix(kv, "REACTOR_WORKFLOW=") {
			continue
		}
		env = append(env, kv)
	}
	// The SDK uses this marker to install the SSRF-safe HTTP transport inside
	// workflow subprocesses. It is appended last so even a test-injected or
	// operator-provided ExtraEnv value cannot spoof or override the value.
	env = append(env, "REACTOR_WORKFLOW=1")
	return env
}

// childEnvForWorkDir adds the process metadata and temporary-directory
// overrides that are unique to one workflow invocation. Keeping this separate
// from childEnv makes it harder for a future caller that does not create a
// private work directory to accidentally inherit the daemon's temporary path.
func childEnvForWorkDir(input []byte, extra []string, workDir string) []string {
	env := childEnv(input, extra)
	return append(env,
		"PWD="+workDir,
		"TMPDIR="+workDir,
		"TMP="+workDir,
		"TEMP="+workDir,
	)
}

func (d *dispatcher) nextID() int64 { return d.frames.Add(1) }

func (d *dispatcher) write(f wire.Frame) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.enc.Encode(f)
}

const (
	// A workflow can write arbitrary bytes to stderr. Bound the total amount
	// forwarded to the daemon so a noisy or stuck child cannot turn logs into
	// an unbounded resource sink. Writes after the cap are acknowledged and
	// discarded so the child cannot deadlock on a full pipe.
	maxWorkflowStderrBytes = 256 << 10
	maxWorkflowStderrChunk = 16 << 10
)

// stderrForwarder echoes bounded stderr chunks as warn-level slog events.
type stderrForwarder struct {
	log       *slog.Logger
	forwarded atomic.Int64
	truncated atomic.Bool
}

func newStderrForwarder(log *slog.Logger) io.Writer { return &stderrForwarder{log: log} }

func (s *stderrForwarder) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := len(p)
	counted := s.reserve(n)
	if counted == 0 {
		if s.truncated.CompareAndSwap(false, true) {
			s.log.Warn("workflow stderr truncated", "limit_bytes", maxWorkflowStderrBytes)
		}
		return len(p), nil
	}
	limitReached := counted < n
	p = p[:counted]
	if len(p) > maxWorkflowStderrChunk {
		p = p[:maxWorkflowStderrChunk]
	}
	s.log.Warn("workflow stderr", "line", string(p))
	if limitReached {
		if s.truncated.CompareAndSwap(false, true) {
			s.log.Warn("workflow stderr truncated", "limit_bytes", maxWorkflowStderrBytes)
		}
	}
	return n, nil
}

func (s *stderrForwarder) reserve(want int) int {
	for {
		used := s.forwarded.Load()
		remaining := int64(maxWorkflowStderrBytes) - used
		if remaining <= 0 {
			return 0
		}
		count := int64(want)
		if count > remaining {
			count = remaining
		}
		if s.forwarded.CompareAndSwap(used, used+count) {
			return int(count)
		}
	}
}
