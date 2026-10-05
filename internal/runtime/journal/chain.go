package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// chainQueryer is satisfied by both *sql.DB and *sql.Tx. Keeping the cycle
// walk queryable through a transaction lets topology validation and the
// subsequent trigger write share one database-level serialization boundary.
type chainQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// chainTopologyLockKey serializes chain graph mutations across distributed
// Reactor processes. PostgreSQL uses the transaction-scoped advisory lock;
// SQLite acquires its writer lock through a no-op workflow update instead.
const chainTopologyLockKey int64 = 0x52454143544f504f // "REACTOPO"

// CreateChainTrigger registers a "run-after-another-workflow" trigger.
// downstreamWorkflowID is the workflow that gets dispatched; sourceWorkflowID
// is the workflow whose terminal status drives the chain. on_statuses
// is the comma-separated CSV of source statuses that fire (defaults to
// "succeeded" if empty).
//
// Storing the source + on_statuses in config_json keeps the schema
// unchanged from migration 0004; we just claim a new kind value on
// the existing triggers table.
func (j *Journal) CreateChainTrigger(ctx context.Context, downstreamWorkflowID, sourceWorkflowID, onStatuses string) (string, error) {
	id, _, err := j.createChainTrigger(ctx, downstreamWorkflowID, sourceWorkflowID, onStatuses, "")
	return id, err
}

// CreateChainTriggerWithIdempotency creates or replays a chain trigger under a
// tenant/workflow/kind-scoped caller key.
func (j *Journal) CreateChainTriggerWithIdempotency(ctx context.Context, downstreamWorkflowID, sourceWorkflowID, onStatuses, key string) (id string, replay bool, err error) {
	return j.createChainTrigger(ctx, downstreamWorkflowID, sourceWorkflowID, onStatuses, key)
}

func (j *Journal) createChainTrigger(ctx context.Context, downstreamWorkflowID, sourceWorkflowID, onStatuses, key string) (id string, replay bool, err error) {
	if downstreamWorkflowID == "" || sourceWorkflowID == "" {
		return "", false, fmt.Errorf("journal: downstream and source workflow ids are required")
	}
	if downstreamWorkflowID == sourceWorkflowID {
		return "", false, fmt.Errorf("journal: chain trigger cannot point at itself")
	}
	// Reject cycles, not just self-loops. The new edge is source ->
	// downstream (downstream fires when source completes). A cycle forms
	// if downstream can already reach source through existing chains, so a
	// terminal run would keep re-triggering itself forever. Walk the
	// existing edges from downstream; if we get back to source, refuse.
	// Cross-tenant refusal, same shape as GrantSecret. This validated self-loops
	// and cycles but never that the two workflows belong to the same tenant, so a
	// chain could make one tenant's completed run start another tenant's workflow
	// and hand it the source run's output as input. That is cross-tenant code
	// execution plus a data channel, not just a visibility leak. Both rows must
	// resolve, otherwise a chain naming a nonexistent workflow silently succeeds.
	srcTenant, downTenant, err := j.chainTenants(ctx, sourceWorkflowID, downstreamWorkflowID)
	if err != nil {
		return "", false, err
	}
	if srcTenant != downTenant {
		return "", false, fmt.Errorf("journal: chain trigger refused: source tenant %q != downstream tenant %q (cross-tenant chains are not allowed)", srcTenant, downTenant)
	}
	onStatuses = normaliseStatuses(onStatuses)
	if onStatuses == "" {
		onStatuses = "succeeded"
	}
	cfg, err := json.Marshal(map[string]string{
		"source_workflow_id": sourceWorkflowID,
		"on_statuses":        onStatuses,
	})
	if err != nil {
		return "", false, fmt.Errorf("journal: chain trigger config: %w", err)
	}
	tx, err := j.beginChainTopologyTx(ctx, downstreamWorkflowID)
	if err != nil {
		return "", false, fmt.Errorf("journal: lock chain topology: %w", err)
	}
	defer tx.Rollback()
	if key != "" {
		var existingID string
		var existingCfg []byte
		row := tx.QueryRowContext(ctx, j.bind(`SELECT id, config_json FROM triggers WHERE workflow_id = $1 AND kind = $2 AND idempotency_key = $3`), downstreamWorkflowID, string(TriggerWorkflowComplete), key)
		if err := row.Scan(&existingID, &existingCfg); err == nil {
			if !bytes.Equal(bytes.TrimSpace(existingCfg), bytes.TrimSpace(cfg)) {
				return "", false, ErrTriggerIdempotencyConflict
			}
			return existingID, true, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return "", false, fmt.Errorf("journal: read chain idempotency record: %w", err)
		}
	}
	// Replay lookup above intentionally precedes cycle detection: a retry of an
	// accepted request must return its original trigger even if later topology
	// changes would make a fresh edge invalid.
	if cyclic, err := chainWouldCycleExcluding(ctx, tx, sourceWorkflowID, downstreamWorkflowID, ""); err != nil {
		return "", false, err
	} else if cyclic {
		return "", false, fmt.Errorf("journal: chain trigger would create a cycle (%s already chains back to %s)", downstreamWorkflowID, sourceWorkflowID)
	}
	id, err = newID("trg_")
	if err != nil {
		return "", false, err
	}
	// As with webhook and cron triggers, ownership is inherited from the
	// downstream workflow atomically rather than falling through to the schema's
	// default tenant.
	const q = `INSERT INTO triggers (id, tenant_id, workflow_id, kind, config_json, state, source_workflow_id, idempotency_key)
		SELECT $1, tenant_id, id, $2, $3, 'active', $4, $5
		FROM workflows WHERE id = $6
		ON CONFLICT DO NOTHING`
	res, err := tx.ExecContext(ctx, j.bind(q), id, string(TriggerWorkflowComplete), outputArg(cfg, j.engine), sourceWorkflowID, nullable(key), downstreamWorkflowID)
	if err != nil {
		return "", false, fmt.Errorf("journal: create chain trigger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", false, fmt.Errorf("journal: create chain trigger rows affected: %w", err)
	}
	if n == 1 {
		if err := tx.Commit(); err != nil {
			return "", false, fmt.Errorf("journal: commit chain trigger: %w", err)
		}
		return id, false, nil
	}
	if key == "" {
		if err := tx.Commit(); err != nil {
			return "", false, fmt.Errorf("journal: commit chain trigger: %w", err)
		}
		return "", false, ErrNotFound
	}
	var existingID string
	var existingCfg []byte
	row := tx.QueryRowContext(ctx, j.bind(`SELECT id, config_json FROM triggers WHERE workflow_id = $1 AND kind = $2 AND idempotency_key = $3`), downstreamWorkflowID, string(TriggerWorkflowComplete), key)
	if err := row.Scan(&existingID, &existingCfg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, ErrNotFound
		}
		return "", false, fmt.Errorf("journal: read chain idempotency record: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(existingCfg), bytes.TrimSpace(cfg)) {
		return "", false, ErrTriggerIdempotencyConflict
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("journal: commit chain trigger: %w", err)
	}
	return existingID, true, nil
}

// beginChainTopologyTx starts the serialization boundary used by chain graph
// mutations. The PostgreSQL advisory lock is transaction-scoped and therefore
// releases automatically on every return path. SQLite has no advisory-lock
// equivalent; a no-op UPDATE takes its database writer lock before the cycle
// query, so two processes cannot validate disjoint edges against the same old
// topology and then both insert.
func (j *Journal) beginChainTopologyTx(ctx context.Context, workflowID string) (*sql.Tx, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if j.engine == EnginePostgres {
		if _, err := tx.ExecContext(ctx, j.bind(`SELECT pg_advisory_xact_lock($1)`), chainTopologyLockKey); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		return tx, nil
	}
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET id = id WHERE id = $1`), workflowID); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return tx, nil
}

// chainEdge is one source -> downstream relationship in the chain graph.
type chainEdge struct {
	id         string
	source     string
	downstream string
}

// allChainEdges loads every active chain trigger as a (source, downstream)
// edge. Chain trigger counts are operator-bounded (dozens), so a full scan
// is cheap and keeps cycle detection simple.
func (j *Journal) allChainEdges(ctx context.Context) ([]chainEdge, error) {
	return allChainEdgesFrom(ctx, j.db)
}

func allChainEdgesFrom(ctx context.Context, q chainQueryer) ([]chainEdge, error) {
	const query = `SELECT id, workflow_id, source_workflow_id FROM triggers
		WHERE kind = $1 AND state = 'active' AND source_workflow_id IS NOT NULL`
	rows, err := q.QueryContext(ctx, query, string(TriggerWorkflowComplete))
	if err != nil {
		return nil, fmt.Errorf("journal: load chain edges: %w", err)
	}
	defer rows.Close()
	var edges []chainEdge
	for rows.Next() {
		var edge chainEdge
		if err := rows.Scan(&edge.id, &edge.downstream, &edge.source); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

// chainWouldCycle reports whether adding the edge source -> downstream
// would close a cycle, i.e. whether downstream can already reach source
// by following existing chain edges. BFS over the operator-bounded edge
// set.
func (j *Journal) chainWouldCycle(ctx context.Context, source, downstream string) (bool, error) {
	return j.chainWouldCycleExcluding(ctx, source, downstream, "")
}

// chainWouldCycleExcluding is the cycle check used when an existing chain
// trigger is being edited. The old edge must be removed from the graph before
// testing the candidate edge; otherwise a valid rewire can be rejected because
// the edge being replaced is itself part of the path back to the candidate
// source.
func (j *Journal) chainWouldCycleExcluding(ctx context.Context, source, downstream, excludeTriggerID string) (bool, error) {
	return chainWouldCycleExcluding(ctx, j.db, source, downstream, excludeTriggerID)
}

func chainWouldCycleExcluding(ctx context.Context, q chainQueryer, source, downstream, excludeTriggerID string) (bool, error) {
	edges, err := allChainEdgesFrom(ctx, q)
	if err != nil {
		return false, err
	}
	adj := map[string][]string{}
	for _, e := range edges {
		if excludeTriggerID != "" && e.id == excludeTriggerID {
			continue
		}
		adj[e.source] = append(adj[e.source], e.downstream)
	}
	seen := map[string]bool{downstream: true}
	queue := []string{downstream}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if node == source {
			return true, nil
		}
		for _, next := range adj[node] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return false, nil
}

// UpdateChainTriggerForWorkflowIfRevision rewires an existing workflow-chain
// trigger while preserving its id and revision history. Both endpoints must
// remain in the same tenant, the candidate graph must stay acyclic, and the
// mutation is applied only when the downstream trigger row still has the
// caller's expected revision.
func (j *Journal) UpdateChainTriggerForWorkflowIfRevision(ctx context.Context, triggerID, downstreamWorkflowID, sourceWorkflowID, onStatuses string, expectedRevision int64) error {
	if expectedRevision < 1 {
		return fmt.Errorf("journal: trigger revision must be positive")
	}
	if triggerID == "" || downstreamWorkflowID == "" || sourceWorkflowID == "" {
		return ErrNotFound
	}
	if downstreamWorkflowID == sourceWorkflowID {
		return fmt.Errorf("journal: chain trigger cannot point at itself")
	}
	srcTenant, downTenant, err := j.chainTenants(ctx, sourceWorkflowID, downstreamWorkflowID)
	if err != nil {
		return err
	}
	if srcTenant != downTenant {
		return fmt.Errorf("journal: chain trigger refused: source tenant %q != downstream tenant %q (cross-tenant chains are not allowed)", srcTenant, downTenant)
	}
	onStatuses = normaliseStatuses(onStatuses)
	if onStatuses == "" {
		onStatuses = "succeeded"
	}
	tx, err := j.beginChainTopologyTx(ctx, downstreamWorkflowID)
	if err != nil {
		return fmt.Errorf("journal: lock chain topology: %w", err)
	}
	defer tx.Rollback()
	if cyclic, err := chainWouldCycleExcluding(ctx, tx, sourceWorkflowID, downstreamWorkflowID, triggerID); err != nil {
		return err
	} else if cyclic {
		return fmt.Errorf("journal: chain trigger would create a cycle (%s already chains back to %s)", downstreamWorkflowID, sourceWorkflowID)
	}
	cfg, err := json.Marshal(map[string]string{"source_workflow_id": sourceWorkflowID, "on_statuses": onStatuses})
	if err != nil {
		return fmt.Errorf("journal: chain trigger config: %w", err)
	}
	const q = `UPDATE triggers SET config_json = $1, source_workflow_id = $2,
		updated_at = $3, revision = revision + 1
		WHERE id = $4 AND workflow_id = $5 AND kind = 'workflow_complete'
		  AND tenant_id IN (SELECT tenant_id FROM workflows WHERE id = $6)
		  AND revision = $7`
	res, err := tx.ExecContext(ctx, j.bind(q), outputArg(cfg, j.engine), sourceWorkflowID, j.now(), triggerID, downstreamWorkflowID, downstreamWorkflowID, expectedRevision)
	if err != nil {
		return fmt.Errorf("journal: update chain trigger for workflow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: update chain trigger for workflow rows affected: %w", err)
	}
	if n != 1 {
		_ = tx.Rollback()
		return j.triggerRevisionConflictOrNotFound(ctx, triggerID, downstreamWorkflowID, expectedRevision)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit chain trigger update: %w", err)
	}
	return nil
}

// ChainTriggersForSource returns the downstream triggers that should
// fire when sourceWorkflowID terminated with status. The chain config
// CSV is checked here so the dispatcher does not need to re-parse.
func (j *Journal) ChainTriggersForSource(ctx context.Context, sourceWorkflowID, status string) ([]Trigger, error) {
	// Filter on the indexed source_workflow_id column instead of scanning
	// every workflow_complete trigger and parsing the source out of JSON.
	// The joins are a runtime fence for restored/imported rows. Trigger writes
	// derive tenant_id from the downstream workflow, but an older database may
	// contain a stale marker or a cross-tenant source_workflow_id. Such a row
	// must never turn one tenant's terminal run into another tenant's code
	// execution or data channel. Keep only rows where all three identities
	// agree; malformed legacy rows simply disappear from the dispatch set.
	const q = `SELECT t.id, t.tenant_id, t.workflow_id, t.kind, t.config_json, t.state, t.token_id, t.secret_id, t.provider, t.last_fired_at, t.last_error, t.created_at, t.updated_at, t.revision
		FROM triggers t
		JOIN workflows src ON src.id = t.source_workflow_id
		JOIN workflows dst ON dst.id = t.workflow_id
		WHERE t.kind = $1 AND t.state = 'active' AND t.source_workflow_id = $2
		  AND t.tenant_id = src.tenant_id
		  AND t.tenant_id = dst.tenant_id`
	rows, err := j.db.QueryContext(ctx, j.bind(q), string(TriggerWorkflowComplete), sourceWorkflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: chain triggers for source: %w", err)
	}
	defer rows.Close()
	all, err := scanTriggerRows(rows, j)
	if err != nil {
		return nil, err
	}
	var out []Trigger
	for _, t := range all {
		var cfg struct {
			OnStatuses string `json:"on_statuses"`
		}
		if err := json.Unmarshal(t.Config, &cfg); err != nil {
			continue // malformed row; skip rather than fail every chain
		}
		if !routeFiresOn(cfg.OnStatuses, status) {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// ChainTriggersDownstreamOf lists chain triggers whose source is
// sourceWorkflowID. Used by the workflow detail page so the operator
// can see what downstream workflows fire from this one.
type ChainTriggerView struct {
	TriggerID            string
	DownstreamWorkflowID string
	DownstreamSlug       string
	// DownstreamTenantID is carried with the slug so dashboard links can
	// disambiguate duplicate slugs when a global operator is viewing a chain.
	// Slugs are unique per tenant, not globally.
	DownstreamTenantID string
	OnStatuses         string
}

func (j *Journal) ChainTriggersDownstreamOf(ctx context.Context, sourceWorkflowID string) ([]ChainTriggerView, error) {
	const q = `SELECT t.id, t.workflow_id, w.slug, w.tenant_id, t.config_json
		FROM triggers t
		JOIN workflows src ON src.id = t.source_workflow_id AND src.tenant_id = t.tenant_id
		JOIN workflows w ON w.id = t.workflow_id AND w.tenant_id = t.tenant_id
		WHERE t.kind = $1 AND t.state = 'active' AND t.source_workflow_id = $2`
	rows, err := j.db.QueryContext(ctx, j.bind(q), string(TriggerWorkflowComplete), sourceWorkflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: chain triggers downstream of: %w", err)
	}
	defer rows.Close()
	var out []ChainTriggerView
	for rows.Next() {
		var row ChainTriggerView
		var cfgBytes []byte
		if err := rows.Scan(&row.TriggerID, &row.DownstreamWorkflowID, &row.DownstreamSlug, &row.DownstreamTenantID, &cfgBytes); err != nil {
			return nil, err
		}
		var cfg struct {
			OnStatuses string `json:"on_statuses"`
		}
		if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
			continue
		}
		row.OnStatuses = cfg.OnStatuses
		out = append(out, row)
	}
	return out, rows.Err()
}

// ChainTriggersUpstreamOf lists chain triggers whose downstream is
// workflowID. Used by the workflow detail page so the operator can
// see what upstream workflows feed into this one.
type ChainUpstreamView struct {
	TriggerID        string
	SourceWorkflowID string
	SourceSlug       string
	OnStatuses       string
}

func (j *Journal) ChainTriggersUpstreamOf(ctx context.Context, workflowID string) ([]ChainUpstreamView, error) {
	const q = `SELECT t.id, t.workflow_id, t.config_json FROM triggers t
		JOIN workflows dst ON dst.id = t.workflow_id AND dst.tenant_id = t.tenant_id
		JOIN workflows src ON src.id = t.source_workflow_id AND src.tenant_id = t.tenant_id
		WHERE t.kind = $1 AND t.workflow_id = $2 AND t.state = 'active'`
	rows, err := j.db.QueryContext(ctx, j.bind(q), string(TriggerWorkflowComplete), workflowID)
	if err != nil {
		return nil, fmt.Errorf("journal: chain triggers upstream of: %w", err)
	}
	defer rows.Close()
	var out []ChainUpstreamView
	for rows.Next() {
		var row ChainUpstreamView
		var dummy string
		var cfgBytes []byte
		if err := rows.Scan(&row.TriggerID, &dummy, &cfgBytes); err != nil {
			return nil, err
		}
		var cfg struct {
			SourceWorkflowID string `json:"source_workflow_id"`
			OnStatuses       string `json:"on_statuses"`
		}
		if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
			continue
		}
		row.SourceWorkflowID = cfg.SourceWorkflowID
		row.OnStatuses = cfg.OnStatuses
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Second pass: resolve source slugs. Cheap: chain trigger counts
	// are operator-bounded (dozens, not thousands).
	for i := range out {
		slug, err := j.WorkflowSlugByID(ctx, out[i].SourceWorkflowID)
		if err == nil {
			out[i].SourceSlug = slug
		}
	}
	return out, nil
}

// chainTenants resolves the owning tenants of both ends of a chain edge,
// refusing when either workflow is missing. Mirrors grantTenants and
// routeTenants: three relations in this schema now enforce the same rule, and
// GrantSecret used to be the only one that did.
func (j *Journal) chainTenants(ctx context.Context, sourceWorkflowID, downstreamWorkflowID string) (string, string, error) {
	lookup := func(id string) (string, error) {
		var tenant sql.NullString
		err := j.db.QueryRowContext(ctx,
			j.bind(`SELECT tenant_id FROM workflows WHERE id = $1`), id).Scan(&tenant)
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("journal: chain trigger: unknown workflow %q", id)
		}
		if err != nil {
			return "", fmt.Errorf("journal: chain trigger: lookup workflow tenant: %w", err)
		}
		return tenant.String, nil
	}
	src, err := lookup(sourceWorkflowID)
	if err != nil {
		return "", "", err
	}
	down, err := lookup(downstreamWorkflowID)
	if err != nil {
		return "", "", err
	}
	return src, down, nil
}
