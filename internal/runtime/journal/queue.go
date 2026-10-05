package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrLeaseOwnershipLost means the caller no longer owns the exact generation
// of a run lease it was given. Callers must stop the workflow immediately: a
// reaper may already have handed the run to a replacement worker.
var ErrLeaseOwnershipLost = errors.New("journal: run lease ownership lost")

// RunLease is one queue claim. Owner is an opaque, unique-per-claim fencing
// token. It deliberately differs from the stable worker id used by the fleet
// registry: every heartbeat, terminal transition, and release must present
// this exact value so an expired process cannot mutate a replacement claim.
type RunLease struct {
	RunID string
	Owner string
}

// This file is the pull-queue + worker-lease surface that backs Reactor's
// distributed mode. In single-node (local) mode the dispatcher executes a
// run in-process and never touches these. In distributed mode the daemon
// ENQUEUES runs (status "queued") and one or more `reactor worker`
// processes claim them atomically and execute them.
//
// The queue IS the runs table; the claim is a row lease. On Postgres the
// claim uses SELECT ... FOR UPDATE SKIP LOCKED so N workers never grab the
// same run. On SQLite (local only; distributed mode requires Postgres) the
// single-writer serialization makes the same select-then-update atomic, so
// the logic is testable without a Postgres instance.

// CreateQueuedRun records a run to be executed by a worker. Unlike
// CreateRun it leaves status "queued" and started_at NULL; a worker sets
// status "running" + started_at when it claims the run.
func (j *Journal) CreateQueuedRun(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta json.RawMessage) error {
	p, err := j.prepareRunPayload(ctx, j.db, workflowID, runID, triggerMeta)
	if err != nil {
		return err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, created_at, tenant_id, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9, $10)`
	if _, err := j.db.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, j.now(), p.tenantID, inputSHA256(triggerMeta), p.cryptoVersion, p.plaintextBytes); err != nil {
		return fmt.Errorf("journal: create queued run: %w", err)
	}
	return nil
}

// CreateQueuedRunPinned writes the queue row and both execution pins in one
// INSERT. There is no crash window in which a claimable row exists without its
// exact workflow version and immutable artifact identity.
func (j *Journal) CreateQueuedRunPinned(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta json.RawMessage, workflowVersion int, artifactSHA256 string) error {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return fmt.Errorf("journal: create pinned queued run: %w", ErrWorkflowArtifactFence)
	}
	p, err := j.prepareRunPayload(ctx, j.db, workflowID, runID, triggerMeta)
	if err != nil {
		return err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9, $10, $11, $12)`
	if _, err := j.db.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, j.now(), p.tenantID, workflowVersion, artifactSHA256, inputSHA256(triggerMeta), p.cryptoVersion, p.plaintextBytes); err != nil {
		return fmt.Errorf("journal: create queued run: %w", err)
	}
	return nil
}

// CreateQueuedRunPinnedIfEnabled atomically admits a queued live run only
// while the workflow is enabled. The worker still rechecks the flag when it
// claims the row, but this closes the dispatch-side race that could otherwise
// enqueue after an operator's disable committed.
func (j *Journal) CreateQueuedRunPinnedIfEnabled(ctx context.Context, runID, workflowID, triggerKind string, triggerMeta json.RawMessage, workflowVersion int, artifactSHA256 string) error {
	if workflowVersion <= 0 || !validArtifactSHA256(artifactSHA256) {
		return fmt.Errorf("journal: create enabled pinned queued run: %w", ErrWorkflowArtifactFence)
	}
	tx, err := j.beginEnabledWorkflowTx(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("journal: create enabled pinned queued run: %w", err)
	}
	defer tx.Rollback()
	if err := j.checkWorkflowAdmissionTx(ctx, tx, workflowID, true); err != nil {
		return fmt.Errorf("journal: create enabled pinned queued run: %w", err)
	}
	p, err := j.prepareRunPayload(ctx, tx, workflowID, runID, triggerMeta)
	if err != nil {
		return err
	}
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, trigger_input, status, created_at, tenant_id, workflow_version, workflow_artifact_sha256, dispatch_payload_sha256, payload_crypto_version, payload_plaintext_bytes)
		VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9, $10, $11, $12)`
	if _, err := tx.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, p.meta, p.input, j.now(), p.tenantID, workflowVersion, artifactSHA256, inputSHA256(triggerMeta), p.cryptoVersion, p.plaintextBytes); err != nil {
		return fmt.Errorf("journal: create enabled pinned queued run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit enabled pinned queued run: %w", err)
	}
	return nil
}

// ClaimQueuedRuns atomically leases up to limit queued runs for workerID,
// flips them to "running", and writes a lease row per run. Returns exact
// claim generations (possibly empty). leaseTTL is how long the claim is
// valid before ReapExpiredLeases may requeue the run (a worker extends its
// lease via ExtendLease while executing).
func (j *Journal) ClaimQueuedRuns(ctx context.Context, workerID string, limit int, leaseTTL time.Duration) ([]RunLease, error) {
	if strings.TrimSpace(workerID) == "" {
		return nil, errors.New("journal: claim queued runs: empty worker id")
	}
	if limit <= 0 {
		limit = 1
	}
	// The count after the tenant row lock must see claims committed while this
	// transaction waited. Force a fresh snapshot for each statement even if
	// the server's default isolation level was raised by an operator.
	var txOpts *sql.TxOptions
	if j.engine == EnginePostgres {
		txOpts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := j.db.BeginTx(ctx, txOpts)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		// SQLite has no SELECT ... FOR UPDATE. Acquire its single-writer lock
		// before reading enabled flags so SetWorkflowEnabled and a queue claim
		// have a deterministic winner.
		if _, err := tx.ExecContext(ctx, `UPDATE workflows SET id = id
			WHERE id IN (SELECT workflow_id FROM runs WHERE status = 'queued')`); err != nil {
			return nil, fmt.Errorf("journal: lock queued workflow state: %w", err)
		}
	}

	// Pick candidates tenant-fairly (interleaved by per-tenant queue position,
	// disabled tenants skipped, over-concurrency tenants dropped). This select
	// does not lock -- it uses window functions, which Postgres forbids
	// combining with FOR UPDATE -- so on Postgres we lock the chosen subset in
	// a second pass. Fetch more candidates than needed so SKIP LOCKED
	// contention between workers does not starve a claim.
	// The public limit is "up to". Keep a single poll's candidate work capped
	// even if an operator configures a much larger worker batch.
	candLimit := 256
	if limit < 64 {
		candLimit = max(8, limit*4)
	}
	candidates, err := scanIDs(tx.QueryContext(ctx, j.bind(j.fairCandidateQuery(candLimit))))
	if err != nil {
		return nil, fmt.Errorf("journal: claim candidate select: %w", err)
	}
	if len(candidates) == 0 {
		return nil, tx.Commit()
	}

	var ids []string
	if j.engine == EnginePostgres {
		// Lock the still-queued, unlocked subset; SKIP LOCKED makes concurrent
		// claimers grab disjoint run rows. A shared workflow lock lets workers
		// claim different runs of the same workflow concurrently while still
		// fencing a concurrent enable/disable UPDATE. The candidate query's concurrency
		// projection is only a scheduling hint: another transaction can start
		// runs before this one commits. Recheck the budget under each tenant's
		// row lock below, before changing any run status.
		tenantByRun, err := j.lockQueuedCandidatesTx(ctx, tx, candidates)
		if err != nil {
			return nil, err
		}
		// When another claimer holds the whole first window, a worker would
		// otherwise report an empty queue despite runnable rows behind it.
		// Expand once, only when the first window was full and row locks left
		// slots unused. Cap the second window at 256 candidates so contention
		// cannot turn one poll into an unbounded lock or placeholder list;
		// this still covers a 32-slot worker's usual 128-candidate first pass.
		const retryMaxCandidates = 256
		if len(tenantByRun) < limit && len(candidates) == candLimit && candLimit < retryMaxCandidates {
			retryLimit := min(candLimit*2, retryMaxCandidates)
			retry, err := scanIDs(tx.QueryContext(ctx, j.bind(j.fairCandidateQuery(retryLimit))))
			if err != nil {
				return nil, fmt.Errorf("journal: claim candidate retry: %w", err)
			}
			seen := make(map[string]bool, len(candidates))
			for _, id := range candidates {
				seen[id] = true
			}
			additional := make([]string, 0, retryMaxCandidates-len(candidates))
			for _, id := range retry {
				if !seen[id] && len(additional) < cap(additional) {
					seen[id] = true
					additional = append(additional, id)
				}
			}
			if len(additional) > 0 {
				newLocked, err := j.lockQueuedCandidatesTx(ctx, tx, additional)
				if err != nil {
					return nil, err
				}
				for id, tenantID := range newLocked {
					tenantByRun[id] = tenantID
				}
				candidates = append(candidates, additional...)
			}
		}
		// IN does not preserve the tenant-fair order. Do not trim before the
		// quota recheck: a tenant that filled its last slot while this claim
		// waited should not prevent another tenant's work from using the batch.
		locked := make([]string, 0, len(tenantByRun))
		for _, id := range candidates {
			if _, ok := tenantByRun[id]; ok {
				locked = append(locked, id)
			}
		}
		ids, err = j.admitLockedTenantClaimsTx(ctx, tx, locked, tenantByRun, limit)
		if err != nil {
			return nil, err
		}
	} else {
		// SQLite serializes writers, so the candidates are already safe to
		// claim; just take up to limit in fair order.
		if len(candidates) > limit {
			candidates = candidates[:limit]
		}
		ids = candidates
	}
	if len(ids) == 0 {
		return nil, tx.Commit()
	}

	expires := j.formatTime(time.Now().UTC().Add(leaseTTL))
	claims := make([]RunLease, 0, len(ids))
	for _, id := range ids {
		owner, err := newLeaseOwner(workerID)
		if err != nil {
			return nil, err
		}
		res, err := tx.ExecContext(ctx,
			j.bind(`UPDATE runs SET status = 'running', started_at = $1
				WHERE id = $2 AND status = 'queued' AND cancel_requested = $3`),
			j.now(), id, j.boolValue(false))
		if err != nil {
			return nil, fmt.Errorf("journal: claim mark running: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, fmt.Errorf("journal: claim mark running: run %s changed concurrently", id)
		}
		if _, err := tx.ExecContext(ctx,
			j.bind(`INSERT INTO leases (run_id, worker_id, expires_at) VALUES ($1, $2, $3)`),
			id, owner, expires); err != nil {
			return nil, fmt.Errorf("journal: claim lease insert: %w", err)
		}
		claims = append(claims, RunLease{RunID: id, Owner: owner})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claims, nil
}

// lockQueuedCandidatesTx acquires run and workflow locks for the given
// advisory candidates. The caller restores tenant-fair order after this
// unordered IN query, and rechecks tenant caps under policy locks.
func (j *Journal) lockQueuedCandidatesTx(ctx context.Context, tx *sql.Tx, candidates []string) (map[string]string, error) {
	ph := make([]string, len(candidates))
	args := make([]any, len(candidates))
	for i, id := range candidates {
		ph[i] = "$" + strconv.Itoa(i+1)
		args[i] = id
	}
	lockQ := `SELECT r.id, r.tenant_id FROM runs r
		JOIN workflows w ON w.id = r.workflow_id
		WHERE r.status = 'queued' AND r.cancel_requested = false
		AND w.enabled = true AND r.tenant_id = w.tenant_id AND r.id IN (` +
		strings.Join(ph, ",") + `) FOR UPDATE OF r SKIP LOCKED FOR SHARE OF w SKIP LOCKED`
	rows, err := tx.QueryContext(ctx, lockQ, args...)
	if err != nil {
		return nil, fmt.Errorf("journal: claim lock: %w", err)
	}
	defer rows.Close()
	tenantByRun := make(map[string]string, len(candidates))
	for rows.Next() {
		var id, tenantID string
		if err := rows.Scan(&id, &tenantID); err != nil {
			return nil, fmt.Errorf("journal: scan claim lock: %w", err)
		}
		tenantByRun[id] = tenantID
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: read claim locks: %w", err)
	}
	return tenantByRun, nil
}

// admitLockedTenantClaimsTx turns a fair but possibly stale Postgres candidate
// list into an exact tenant-bounded claim set. Every claimer locks tenant rows
// in the same order. For a capped tenant, the exclusive row lock serializes
// the recount under READ COMMITTED: the second claimer sees the first one's
// committed running rows. Unlimited tenants use compatible shared locks. The
// policy row locks also coordinate with live admission and tenant edits.
func (j *Journal) admitLockedTenantClaimsTx(ctx context.Context, tx *sql.Tx, locked []string, tenantByRun map[string]string, limit int) ([]string, error) {
	if len(locked) == 0 {
		return nil, nil
	}
	tenantSet := make(map[string]struct{}, len(locked))
	for _, id := range locked {
		tenantSet[tenantByRun[id]] = struct{}{}
	}
	tenantIDs := make([]string, 0, len(tenantSet))
	for tenantID := range tenantSet {
		tenantIDs = append(tenantIDs, tenantID)
	}
	sort.Strings(tenantIDs)
	remaining := make(map[string]int, len(tenantIDs))
	disabled := make(map[string]bool, len(tenantIDs))
	for _, tenantID := range tenantIDs {
		tenant, exists, becameCapped, err := j.lockTenantForClaimTx(ctx, tx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("journal: claim tenant admission: %w", err)
		}
		if !exists {
			continue // legacy workflow tenant without a registry row is unlimited
		}
		if tenant.Disabled || becameCapped {
			disabled[tenantID] = true
			continue
		}
		if tenant.MaxConcurrentRuns > 0 {
			running, err := j.countRunsTx(ctx, tx,
				`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status = 'running'`, tenantID)
			if err != nil {
				return nil, fmt.Errorf("journal: claim tenant running count: %w", err)
			}
			remaining[tenantID] = tenant.MaxConcurrentRuns - running
		}
	}
	ids := make([]string, 0, min(limit, len(locked)))
	for _, id := range locked {
		tenantID := tenantByRun[id]
		if disabled[tenantID] {
			continue
		}
		if slots, capped := remaining[tenantID]; capped {
			if slots <= 0 {
				continue
			}
			remaining[tenantID] = slots - 1
		}
		ids = append(ids, id)
		if len(ids) == limit {
			break
		}
	}
	return ids, nil
}

// lockTenantForClaimTx uses a shared row lock for an unlimited tenant, so
// independent workers do not serialize all their claims on the default tenant
// row. A capped tenant needs an exclusive row lock before counting running
// runs. If a policy edit adds a cap between the first read and the shared
// lock, this batch skips that tenant; the next poll will take the exclusive
// path. The shared lock still fences disabled/cap edits while a claim commits.
func (j *Journal) lockTenantForClaimTx(ctx context.Context, tx *sql.Tx, tenantID string) (Tenant, bool, bool, error) {
	if j.engine != EnginePostgres {
		tenant, exists, err := j.lockTenantTx(ctx, tx, tenantID)
		return tenant, exists, false, err
	}
	var initialCap int
	err := tx.QueryRowContext(ctx, `SELECT max_concurrent_runs FROM tenants WHERE tenant_id = $1`, tenantID).Scan(&initialCap)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, false, false, nil
	}
	if err != nil {
		return Tenant{}, false, false, fmt.Errorf("journal: read tenant claim policy: %w", err)
	}
	lockMode := ` FOR SHARE`
	if initialCap > 0 {
		lockMode = ` FOR UPDATE`
	}
	tenant, err := j.scanTenant(tx.QueryRowContext(ctx,
		`SELECT `+tenantCols+` FROM tenants WHERE tenant_id = $1`+lockMode, tenantID))
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, false, false, nil
	}
	if err != nil {
		return Tenant{}, false, false, fmt.Errorf("journal: lock tenant claim policy: %w", err)
	}
	return tenant, true, initialCap <= 0 && tenant.MaxConcurrentRuns > 0, nil
}

func newLeaseOwner(workerID string) (string, error) {
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return "", fmt.Errorf("journal: create lease generation: %w", err)
	}
	return workerID + "/" + hex.EncodeToString(generation[:]), nil
}

// VerifyLeaseOwner is the worker's pre-spawn fence. It prevents a stale
// goroutine that was delayed before ExecuteRun from launching after its lease
// deadline or after a reaper has installed another generation. Heartbeats and
// finalization still carry the token because ownership can change after this
// point.
func (j *Journal) VerifyLeaseOwner(ctx context.Context, runID, owner string) error {
	const q = `SELECT 1 FROM leases l
		JOIN runs r ON r.id = l.run_id
		WHERE l.run_id = $1 AND l.worker_id = $2 AND r.status = 'running'
		AND l.expires_at > $3`
	var one int
	err := j.db.QueryRowContext(ctx, j.bind(q), runID, owner, j.formatTime(time.Now().UTC())).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: verify run=%s", ErrLeaseOwnershipLost, runID)
	}
	if err != nil {
		return fmt.Errorf("journal: verify lease owner: %w", err)
	}
	return nil
}

// ExtendLease renews the lease on a run the worker is still executing.
// Only the owning worker can extend, so a reaped+reclaimed run isn't
// renewed by its dead original owner.
func (j *Journal) ExtendLease(ctx context.Context, runID, workerID string, ttl time.Duration) error {
	// Check the old deadline after acquiring the lease lock. A renewal can
	// wait for a database connection or another transaction past its deadline;
	// comparing with a timestamp taken before that wait would revive a stale
	// generation and prevent the reaper from handing it to another worker.
	var txOpts *sql.TxOptions
	if j.engine == EnginePostgres {
		txOpts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := j.db.BeginTx(ctx, txOpts)
	if err != nil {
		return fmt.Errorf("journal: begin lease renewal: %w", err)
	}
	defer tx.Rollback()
	oldDeadline, err := j.lockOwnedLease(ctx, tx, runID, workerID)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE leases SET expires_at = $1
		WHERE run_id = $2 AND worker_id = $3`),
		j.formatTime(time.Now().UTC().Add(ttl)), runID, workerID)
	if err != nil {
		return fmt.Errorf("journal: extend lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: extend run=%s", ErrLeaseOwnershipLost, runID)
	}
	if err := checkOwnedLeaseDeadline(runID, oldDeadline); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit lease renewal: %w", err)
	}
	return nil
}

// ReleaseLease drops a run's lease. Called when the run reaches a terminal
// status so the row no longer counts as in-flight.
func (j *Journal) ReleaseLease(ctx context.Context, runID, owner string) error {
	res, err := j.db.ExecContext(ctx, j.bind(`DELETE FROM leases WHERE run_id = $1 AND worker_id = $2`), runID, owner)
	if err != nil {
		return fmt.Errorf("journal: release lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: release run=%s", ErrLeaseOwnershipLost, runID)
	}
	return nil
}

// ReturnUnstartedLease gives back an exact claim that the worker has not
// passed to ExecuteRun. It is used during shutdown after a batch claim, so
// another worker can take the run without waiting for the lease deadline.
// The caller must not use this for a run whose workflow may have started.
func (j *Journal) ReturnUnstartedLease(ctx context.Context, runID, owner string) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: return unstarted lease: %w", err)
	}
	defer tx.Rollback()
	// Lock the lease before the run, matching reaping and owned finalization.
	// A no-op UPDATE also takes SQLite's writer lock before its status read.
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE leases SET worker_id = worker_id
		WHERE run_id = $1 AND worker_id = $2`), runID, owner)
	if err != nil {
		return fmt.Errorf("journal: lock unstarted lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: return unstarted run=%s", ErrLeaseOwnershipLost, runID)
	}
	runQ := `SELECT status, cancel_requested FROM runs WHERE id = $1`
	if j.engine == EnginePostgres {
		runQ += ` FOR UPDATE`
	}
	var status string
	var cancelRequested any
	if err := tx.QueryRowContext(ctx, j.bind(runQ), runID).Scan(&status, &cancelRequested); err != nil {
		return fmt.Errorf("journal: read unstarted run: %w", err)
	}
	if status != "running" {
		return fmt.Errorf("%w: return unstarted run=%s", ErrLeaseOwnershipLost, runID)
	}
	if parseBool(cancelRequested) {
		// A cancellation accepted while the worker was stopping must become
		// terminal here, not turn back into claimable queue work.
		res, err = tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = 'cancelled', finished_at = $1
			WHERE id = $2 AND status = 'running' AND cancel_requested = $3`),
			j.now(), runID, j.boolValue(true))
		if err != nil {
			return fmt.Errorf("journal: cancel unstarted run: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
			j.boolValue(true), runID, j.boolValue(false)); err != nil {
			return fmt.Errorf("journal: cancel unstarted run schedules: %w", err)
		}
	} else {
		res, err = tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = 'queued'
			WHERE id = $1 AND status = 'running' AND cancel_requested = $2`),
			runID, j.boolValue(false))
		if err != nil {
			return fmt.Errorf("journal: requeue unstarted run: %w", err)
		}
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: return unstarted run=%s", ErrLeaseOwnershipLost, runID)
	}
	res, err = tx.ExecContext(ctx, j.bind(`DELETE FROM leases WHERE run_id = $1 AND worker_id = $2`), runID, owner)
	if err != nil {
		return fmt.Errorf("journal: delete unstarted lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: return unstarted run=%s", ErrLeaseOwnershipLost, runID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit unstarted lease return: %w", err)
	}
	if parseBool(cancelRequested) {
		j.recordUsageBestEffort(ctx, runID, "cancelled")
	}
	return nil
}

const expiredLeaseReapBatch = 128

// ReapExpiredLeases requeues up to expiredLeaseReapBatch runs whose worker died
// (lease expired while the run was still "running") and drops their stale
// leases. Re-running is safe: the supervisor replays completed steps from the
// journal cache, so a requeued run resumes rather than repeating side effects.
// Repeated ticks drain a larger backlog, oldest leases first. Returns the
// number of runs requeued; cancelled and already-terminal leases do not count.
func (j *Journal) ReapExpiredLeases(ctx context.Context) (int64, error) {
	var txOpts *sql.TxOptions
	if j.engine == EnginePostgres {
		// A renewal committed while this transaction waited must be visible to
		// the expired-row predicate before it is locked and acted upon.
		txOpts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := j.db.BeginTx(ctx, txOpts)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := j.formatTime(time.Now().UTC())
	// PostgreSQL's FOR UPDATE makes renewal and reaping mutually exclusive.
	// SQLite transactions begin deferred, so take its single-writer lock with a
	// no-op UPDATE before selecting the exact expired generations. Update only
	// the oldest row: updating the whole expired backlog would hold the writer
	// lock for unbounded work before the capped SELECT even starts.
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE leases SET worker_id = worker_id
			WHERE run_id = (SELECT run_id FROM leases WHERE expires_at < $1
				ORDER BY expires_at LIMIT 1)`), now); err != nil {
			return 0, fmt.Errorf("journal: lock expired leases: %w", err)
		}
	}
	q := `SELECT run_id, worker_id FROM leases WHERE expires_at < $1
		ORDER BY expires_at LIMIT $2`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE SKIP LOCKED`
	}
	rows, err := tx.QueryContext(ctx, j.bind(q), now, expiredLeaseReapBatch)
	if err != nil {
		return 0, fmt.Errorf("journal: select expired leases: %w", err)
	}
	var expired []RunLease
	for rows.Next() {
		var claim RunLease
		if err := rows.Scan(&claim.RunID, &claim.Owner); err != nil {
			rows.Close()
			return 0, fmt.Errorf("journal: scan expired lease: %w", err)
		}
		expired = append(expired, claim)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("journal: close expired leases: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("journal: iterate expired leases: %w", err)
	}

	var n int64
	var cancelled []string
	for _, claim := range expired {
		// Lock the run after its lease (the same order as owned finalization),
		// then inspect cancel_requested under that lock. A cancel accepted while
		// the old owner was dead must become terminal here, never a queued run a
		// replacement worker can claim.
		runQ := `SELECT status, cancel_requested FROM runs WHERE id = $1`
		if j.engine == EnginePostgres {
			runQ += ` FOR UPDATE`
		}
		var (
			status          string
			cancelRequested any
		)
		if err := tx.QueryRowContext(ctx, j.bind(runQ), claim.RunID).Scan(&status, &cancelRequested); err != nil {
			return 0, fmt.Errorf("journal: lock expired lease run: %w", err)
		}

		if parseBool(cancelRequested) && (status == "running" || status == "queued" || status == "suspended") {
			res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs
				SET status = 'cancelled', finished_at = $1
				WHERE id = $2 AND status = $3 AND cancel_requested = $4`),
				j.now(), claim.RunID, status, j.boolValue(true))
			if err != nil {
				return 0, fmt.Errorf("journal: reap cancelled dead owner: %w", err)
			}
			if moved, _ := res.RowsAffected(); moved != 1 {
				return 0, fmt.Errorf("journal: reap cancelled dead owner: run %s changed concurrently", claim.RunID)
			}
			if _, err := tx.ExecContext(ctx,
				j.bind(`UPDATE schedules SET fired = $1 WHERE run_id = $2 AND fired = $3`),
				j.boolValue(true), claim.RunID, j.boolValue(false)); err != nil {
				return 0, fmt.Errorf("journal: reap cancelled dead owner schedules: %w", err)
			}
			cancelled = append(cancelled, claim.RunID)
		} else if status == "running" {
			res, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET status = 'queued'
				WHERE id = $1 AND status = 'running' AND cancel_requested = $2`),
				claim.RunID, j.boolValue(false))
			if err != nil {
				return 0, fmt.Errorf("journal: reap requeue: %w", err)
			}
			moved, _ := res.RowsAffected()
			if moved != 1 {
				return 0, fmt.Errorf("journal: reap requeue: run %s changed concurrently", claim.RunID)
			}
			n++
		}

		res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM leases
			WHERE run_id = $1 AND worker_id = $2 AND expires_at < $3`), claim.RunID, claim.Owner, now)
		if err != nil {
			return 0, fmt.Errorf("journal: reap delete lease: %w", err)
		}
		if deleted, _ := res.RowsAffected(); deleted != 1 {
			return 0, fmt.Errorf("%w: reap run=%s", ErrLeaseOwnershipLost, claim.RunID)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	for _, runID := range cancelled {
		j.recordUsageBestEffort(ctx, runID, "cancelled")
	}
	return n, nil
}

// fairCandidateQuery builds the tenant-fair, quota-bounded candidate select
// (no locking; the Postgres claim locks the result separately because window
// functions cannot combine with FOR UPDATE). It:
//   - interleaves tenants by per-tenant queue position (ROW_NUMBER partitioned
//     by tenant ordered by created_at), so all tenants' oldest run is offered
//     before any tenant's second -- one tenant's backlog cannot starve others;
//   - skips runs of disabled tenants;
//   - drops runs that would exceed a tenant's max_concurrent_runs (the run's
//     position rn must fit within cap minus currently-running). A tenant with
//     no tenants row, or a 0/NULL cap, is unlimited + enabled.
//
// This query is an advisory scheduling filter. Postgres claims enforce the
// concurrency cap under tenant row locks after SKIP LOCKED selects the rows;
// SQLite claims execute under the single-writer transaction lock. Fair
// interleaving prevents starvation independently of the hard cap. PostgreSQL
// discovers only workflows with currently queued runs through ordered seeks
// on the partial queue index, then returns at most limit eligible rows per
// workflow before ranking. This avoids probing every workflow that has ever
// queued work, or ranking one workflow's deep backlog. Filtered malformed
// rows can still cost index reads before that limit. A queued run whose stored
// tenant differs from its workflow owner is never a candidate: otherwise it
// could be charged to and quota-checked against a different tenant.
func (j *Journal) fairCandidateQuery(limit int) string {
	if j.engine == EnginePostgres {
		return postgresFairCandidateQuery(min(max(limit, 1), 256))
	}
	falseLit := "false"
	trueLit := "true"
	if j.engine == EngineSQLite {
		falseLit = "0"
		trueLit = "1"
	}
	return `WITH running AS (
		SELECT tenant_id, COUNT(*) AS n FROM runs WHERE status = 'running' GROUP BY tenant_id
	),
	ranked AS (
		SELECT r.id, r.tenant_id, r.created_at,
			ROW_NUMBER() OVER (PARTITION BY r.tenant_id ORDER BY r.created_at, r.id) AS rn
		FROM runs r
		JOIN workflows w ON w.id = r.workflow_id
		WHERE r.status = 'queued' AND r.cancel_requested = ` + falseLit + `
		AND w.enabled = ` + trueLit + ` AND r.tenant_id = w.tenant_id
	)
	SELECT k.id
	FROM ranked k
	LEFT JOIN tenants t ON t.tenant_id = k.tenant_id
	LEFT JOIN running ru ON ru.tenant_id = k.tenant_id
	WHERE (t.disabled IS NULL OR t.disabled = ` + falseLit + `)
		AND (t.max_concurrent_runs IS NULL OR t.max_concurrent_runs <= 0
			OR k.rn <= t.max_concurrent_runs - COALESCE(ru.n, 0))
	ORDER BY k.rn, k.created_at, k.id
	LIMIT ` + strconv.Itoa(limit)
}

func postgresFairCandidateQuery(limit int) string {
	// The recursive CTE is a loose index scan: each iteration seeks the next
	// workflow_id in runs_queued_workflow_order_idx. Unlike the append-only
	// queue_workflow_index hint, its cost grows with workflows that currently
	// have queued rows, not workflows that ever queued a run. This also avoids
	// a lost-membership race between a drain and a concurrent enqueue without
	// taking a per-workflow lock on every admission.
	//
	// Fetching the first limit rows of every enabled workflow is sufficient
	// to find any tenant's first limit runnable rows, even if the tenant owns
	// several workflows. The lateral LIMIT bounds ranked rows per workflow;
	// the partial index normally bounds physical reads, though PostgreSQL may
	// choose a general index if its cost estimate says that is cheaper.
	return `WITH RECURSIVE queued_workflows(workflow_id) AS (
		(SELECT workflow_id FROM runs
			WHERE status = 'queued' AND cancel_requested = false
			ORDER BY workflow_id LIMIT 1)
		UNION ALL
		SELECT qnext.workflow_id
		FROM queued_workflows q
		CROSS JOIN LATERAL (
			SELECT workflow_id FROM runs
			WHERE status = 'queued' AND cancel_requested = false
				AND workflow_id > q.workflow_id
			ORDER BY workflow_id LIMIT 1
		) qnext
	),
	per_workflow AS MATERIALIZED (
		SELECT r.id, r.tenant_id, r.created_at
		FROM queued_workflows qi
		JOIN workflows w ON w.id = qi.workflow_id AND w.enabled = true
		CROSS JOIN LATERAL (
			SELECT id, tenant_id, created_at FROM runs
			WHERE workflow_id = w.id AND status = 'queued'
				AND cancel_requested = false AND tenant_id = w.tenant_id
			ORDER BY created_at, id
			LIMIT ` + strconv.Itoa(limit) + `
		) r
	),
	running AS (
		SELECT c.tenant_id, (
			SELECT COUNT(*) FROM runs r WHERE r.tenant_id = c.tenant_id
				AND r.status = 'running'
		) AS n
		FROM (SELECT DISTINCT tenant_id FROM per_workflow) c
		JOIN tenants t ON t.tenant_id = c.tenant_id
		WHERE t.max_concurrent_runs > 0
	),
	ranked AS (
		SELECT r.id, r.tenant_id, r.created_at,
			ROW_NUMBER() OVER (PARTITION BY r.tenant_id ORDER BY r.created_at, r.id) AS rn
		FROM per_workflow r
	)
	SELECT k.id
	FROM ranked k
	LEFT JOIN tenants t ON t.tenant_id = k.tenant_id
	LEFT JOIN running ru ON ru.tenant_id = k.tenant_id
	WHERE (t.disabled IS NULL OR t.disabled = false)
		AND (t.max_concurrent_runs IS NULL OR t.max_concurrent_runs <= 0
			OR k.rn <= t.max_concurrent_runs - COALESCE(ru.n, 0))
	ORDER BY k.rn, k.created_at, k.id
	LIMIT ` + strconv.Itoa(limit)
}

// scanIDs collects a single-column id result set, closing rows.
func scanIDs(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// CountQueued returns how many runs are waiting to be claimed. Powers the
// physical queue-depth /metrics gauge. It deliberately includes policy-blocked
// runs so operators can see work retained under a disabled workflow or tenant.
func (j *Journal) CountQueued(ctx context.Context) (int, error) {
	var n int
	falseLit := "false"
	if j.engine == EngineSQLite {
		falseLit = "0"
	}
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE status = 'queued' AND cancel_requested = `+falseLit)).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: count queued: %w", err)
	}
	return n, nil
}

// CountClaimableQueued is the autoscaler's demand signal. A disabled workflow,
// disabled tenant, cancelled run, or tenant already at its concurrency cap
// cannot be helped by starting another worker. This is an advisory snapshot:
// ClaimQueuedRuns still checks the current policy and locks rows at claim time.
// A run with an inconsistent persisted workflow/tenant identity is excluded
// from both this signal and the claim path. Artifact availability is checked
// by the worker after claim, not here.
func (j *Journal) CountClaimableQueued(ctx context.Context) (int, error) {
	falseLit, trueLit := "false", "true"
	if j.engine == EngineSQLite {
		falseLit, trueLit = "0", "1"
	}
	q := `WITH queued AS (
		SELECT r.tenant_id, COUNT(*) AS n
		FROM runs r
		JOIN workflows w ON w.id = r.workflow_id AND w.enabled = ` + trueLit + `
			AND r.tenant_id = w.tenant_id
		LEFT JOIN tenants t ON t.tenant_id = r.tenant_id
		WHERE r.status = 'queued' AND r.cancel_requested = ` + falseLit + `
			AND (t.disabled IS NULL OR t.disabled = ` + falseLit + `)
		GROUP BY r.tenant_id
	), running AS (
		-- Only capped tenants with eligible queued rows need a running count.
		-- A global GROUP BY over running rows makes a small queue probe cost
		-- grow with unrelated tenants' in-flight work.
		SELECT q.tenant_id, (
			SELECT COUNT(*) FROM runs r
			WHERE r.tenant_id = q.tenant_id AND r.status = 'running'
		) AS n
		FROM queued q
		JOIN tenants t ON t.tenant_id = q.tenant_id
		WHERE t.max_concurrent_runs > 0
	)
	SELECT COALESCE(SUM(CASE
		WHEN t.max_concurrent_runs IS NULL OR t.max_concurrent_runs <= 0 THEN q.n
		WHEN t.max_concurrent_runs <= COALESCE(ru.n, 0) THEN 0
		WHEN q.n <= t.max_concurrent_runs - COALESCE(ru.n, 0) THEN q.n
		ELSE t.max_concurrent_runs - COALESCE(ru.n, 0)
	END), 0)
	FROM queued q
	LEFT JOIN tenants t ON t.tenant_id = q.tenant_id
	LEFT JOIN running ru ON ru.tenant_id = q.tenant_id`
	var n int
	if err := j.db.QueryRowContext(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: count claimable queued: %w", err)
	}
	return n, nil
}

// CountClaimableQueuedUpTo returns min(claimable, saturation). The controller
// needs only enough demand to reach its maximum worker target, whereas the
// metrics gauge continues to expose the exact count. PostgreSQL can use the
// tenant-fair, indexed per-workflow candidate read for saturation values up
// to its 256-row polling bound. The workflow/tenant fence in that query makes
// this cardinality exact up to saturation even if malformed legacy rows are
// interleaved with eligible rows. Larger targets and SQLite use the exact
// query and cap its result instead of undercounting eligible work.
func (j *Journal) CountClaimableQueuedUpTo(ctx context.Context, saturation int) (int, error) {
	if saturation <= 0 {
		return 0, errors.New("journal: count claimable queued: nonpositive saturation")
	}
	if j.engine == EnginePostgres && saturation <= 256 {
		ids, err := scanIDs(j.db.QueryContext(ctx, j.fairCandidateQuery(saturation)))
		if err != nil {
			return 0, fmt.Errorf("journal: count claimable queued up to saturation: %w", err)
		}
		return len(ids), nil
	}
	n, err := j.CountClaimableQueued(ctx)
	if err != nil {
		return 0, err
	}
	return min(n, saturation), nil
}

// OldestQueuedAge reports how long the oldest uncancelled queued run has
// waited. An empty queue has age zero. This uses the same row eligibility as
// CountQueued; disabled workflows can therefore keep this signal elevated
// until their queued rows are cancelled or re-enabled.
func (j *Journal) OldestQueuedAge(ctx context.Context) (time.Duration, error) {
	falseLit := "false"
	if j.engine == EngineSQLite {
		falseLit = "0"
	}
	q := `SELECT created_at FROM runs WHERE status = 'queued' AND cancel_requested = ` + falseLit +
		` ORDER BY created_at, id LIMIT 1`
	var raw any
	if err := j.db.QueryRowContext(ctx, q).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("journal: oldest queued run: %w", err)
	}
	var created time.Time
	switch value := raw.(type) {
	case time.Time:
		created = value.UTC()
	case string:
		var err error
		created, err = j.parseTime(value)
		if err != nil {
			return 0, fmt.Errorf("journal: oldest queued run time: %w", err)
		}
	case []byte:
		var err error
		created, err = j.parseTime(string(value))
		if err != nil {
			return 0, fmt.Errorf("journal: oldest queued run time: %w", err)
		}
	default:
		return 0, fmt.Errorf("journal: oldest queued run has unsupported time type %T", raw)
	}
	age := time.Since(created)
	if age < 0 {
		return 0, nil // clock skew cannot produce a negative backlog age
	}
	return age, nil
}

// CountRunning returns the number of currently claimed distributed runs.
// Autoscaling uses this alongside CountQueued so an empty queue does not look
// idle while every worker slot is still executing a run.
func (j *Journal) CountRunning(ctx context.Context) (int, error) {
	var n int
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE status = 'running'`)).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: count running: %w", err)
	}
	return n, nil
}
