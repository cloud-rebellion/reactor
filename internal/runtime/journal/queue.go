package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	tm := outputArg(triggerMeta, j.engine)
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, status, created_at, tenant_id)
		VALUES ($1, $2, $3, $4, 'queued', $5, COALESCE((SELECT tenant_id FROM workflows WHERE id = $6), 'default'))`
	if _, err := j.db.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, tm, j.now(), workflowID); err != nil {
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
	tm := outputArg(triggerMeta, j.engine)
	// tenant_id is denormalized from the workflow so the fair-share claim and
	// quota counts read it off the run directly (workflowID passed twice
	// because the $N rewriter does not dedupe repeated params).
	const q = `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, status, created_at, tenant_id, workflow_version, workflow_artifact_sha256)
		VALUES ($1, $2, $3, $4, 'queued', $5, COALESCE((SELECT tenant_id FROM workflows WHERE id = $6), 'default'), $7, $8)`
	if _, err := j.db.ExecContext(ctx, j.bind(q), runID, workflowID, triggerKind, tm, j.now(), workflowID, workflowVersion, artifactSHA256); err != nil {
		return fmt.Errorf("journal: create queued run: %w", err)
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
	tx, err := j.db.BeginTx(ctx, nil)
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
	candLimit := limit * 4
	if candLimit < 8 {
		candLimit = 8
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
		// claimers grab disjoint rows. Then re-impose the fair order (IN does
		// not preserve it) and take up to limit.
		ph := make([]string, len(candidates))
		args := make([]any, len(candidates))
		for i, id := range candidates {
			ph[i] = "$" + strconv.Itoa(i+1)
			args[i] = id
		}
		lockQ := `SELECT r.id FROM runs r
			JOIN workflows w ON w.id = r.workflow_id
			WHERE r.status = 'queued' AND r.cancel_requested = false
			AND w.enabled = true AND r.id IN (` +
			strings.Join(ph, ",") + `) FOR UPDATE OF r, w SKIP LOCKED`
		locked, lerr := scanIDs(tx.QueryContext(ctx, lockQ, args...))
		if lerr != nil {
			return nil, fmt.Errorf("journal: claim lock: %w", lerr)
		}
		lockedSet := make(map[string]bool, len(locked))
		for _, id := range locked {
			lockedSet[id] = true
		}
		for _, id := range candidates {
			if lockedSet[id] {
				ids = append(ids, id)
				if len(ids) == limit {
					break
				}
			}
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

func newLeaseOwner(workerID string) (string, error) {
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return "", fmt.Errorf("journal: create lease generation: %w", err)
	}
	return workerID + "/" + hex.EncodeToString(generation[:]), nil
}

// VerifyLeaseOwner is the worker's pre-spawn fence. It prevents a stale
// goroutine that was delayed before ExecuteRun from launching after a reaper
// has already installed another generation. Heartbeats and finalization still
// carry the token because ownership can change after this point.
func (j *Journal) VerifyLeaseOwner(ctx context.Context, runID, owner string) error {
	const q = `SELECT 1 FROM leases l
		JOIN runs r ON r.id = l.run_id
		WHERE l.run_id = $1 AND l.worker_id = $2 AND r.status = 'running'`
	var one int
	err := j.db.QueryRowContext(ctx, j.bind(q), runID, owner).Scan(&one)
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
	const q = `UPDATE leases SET expires_at = $1 WHERE run_id = $2 AND worker_id = $3`
	res, err := j.db.ExecContext(ctx, j.bind(q),
		j.formatTime(time.Now().UTC().Add(ttl)), runID, workerID)
	if err != nil {
		return fmt.Errorf("journal: extend lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: extend run=%s", ErrLeaseOwnershipLost, runID)
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

// ReapExpiredLeases requeues runs whose worker died (lease expired while
// the run was still "running") and drops the stale leases. Re-running is
// safe: the supervisor replays completed steps from the journal cache, so
// a requeued run resumes rather than repeating side effects. Returns the
// number of runs requeued.
func (j *Journal) ReapExpiredLeases(ctx context.Context) (int64, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := j.formatTime(time.Now().UTC())
	// PostgreSQL's FOR UPDATE makes renewal and reaping mutually exclusive.
	// SQLite transactions begin deferred, so take its single-writer lock with a
	// no-op guarded UPDATE before selecting the exact expired generations.
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE leases SET worker_id = worker_id WHERE expires_at < $1`), now); err != nil {
			return 0, fmt.Errorf("journal: lock expired leases: %w", err)
		}
	}
	q := `SELECT run_id, worker_id FROM leases WHERE expires_at < $1`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE SKIP LOCKED`
	}
	rows, err := tx.QueryContext(ctx, j.bind(q), now)
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
// The concurrency cap is enforced best-effort: each claimer reads the running
// count once, so concurrent claimers can briefly overshoot by up to a batch.
// Fair interleaving (not the hard cap) is what prevents starvation.
func (j *Journal) fairCandidateQuery(limit int) string {
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
		AND w.enabled = ` + trueLit + `
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
// worker autoscaler's scale-up signal + a /metrics gauge.
func (j *Journal) CountQueued(ctx context.Context) (int, error) {
	var n int
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE status = 'queued'`)).Scan(&n); err != nil {
		return 0, fmt.Errorf("journal: count queued: %w", err)
	}
	return n, nil
}
