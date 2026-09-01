package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

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
	if downstreamWorkflowID == "" || sourceWorkflowID == "" {
		return "", fmt.Errorf("journal: downstream and source workflow ids are required")
	}
	if downstreamWorkflowID == sourceWorkflowID {
		return "", fmt.Errorf("journal: chain trigger cannot point at itself")
	}
	// Reject cycles, not just self-loops. The new edge is source ->
	// downstream (downstream fires when source completes). A cycle forms
	// if downstream can already reach source through existing chains, so a
	// terminal run would keep re-triggering itself forever. Walk the
	// existing edges from downstream; if we get back to source, refuse.
	if cyclic, err := j.chainWouldCycle(ctx, sourceWorkflowID, downstreamWorkflowID); err != nil {
		return "", err
	} else if cyclic {
		return "", fmt.Errorf("journal: chain trigger would create a cycle (%s already chains back to %s)", downstreamWorkflowID, sourceWorkflowID)
	}
	// Cross-tenant refusal, same shape as GrantSecret. This validated self-loops
	// and cycles but never that the two workflows belong to the same tenant, so a
	// chain could make one tenant's completed run start another tenant's workflow
	// and hand it the source run's output as input. That is cross-tenant code
	// execution plus a data channel, not just a visibility leak. Both rows must
	// resolve, otherwise a chain naming a nonexistent workflow silently succeeds.
	srcTenant, downTenant, err := j.chainTenants(ctx, sourceWorkflowID, downstreamWorkflowID)
	if err != nil {
		return "", err
	}
	if srcTenant != downTenant {
		return "", fmt.Errorf("journal: chain trigger refused: source tenant %q != downstream tenant %q (cross-tenant chains are not allowed)", srcTenant, downTenant)
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
		return "", fmt.Errorf("journal: chain trigger config: %w", err)
	}
	id, err := newID("trg_")
	if err != nil {
		return "", err
	}
	// As with webhook and cron triggers, ownership is inherited from the
	// downstream workflow atomically rather than falling through to the schema's
	// default tenant.
	const q = `INSERT INTO triggers (id, tenant_id, workflow_id, kind, config_json, state, source_workflow_id)
		SELECT $1, tenant_id, id, $2, $3, 'active', $4
		FROM workflows WHERE id = $5`
	res, err := j.db.ExecContext(ctx, j.bind(q), id, string(TriggerWorkflowComplete), outputArg(cfg, j.engine), sourceWorkflowID, downstreamWorkflowID)
	if err != nil {
		return "", fmt.Errorf("journal: create chain trigger: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("journal: create chain trigger rows affected: %w", err)
	}
	if n != 1 {
		return "", ErrNotFound
	}
	return id, nil
}

// chainEdge is one source -> downstream relationship in the chain graph.
type chainEdge struct {
	source     string
	downstream string
}

// allChainEdges loads every active chain trigger as a (source, downstream)
// edge. Chain trigger counts are operator-bounded (dozens), so a full scan
// is cheap and keeps cycle detection simple.
func (j *Journal) allChainEdges(ctx context.Context) ([]chainEdge, error) {
	const q = `SELECT workflow_id, source_workflow_id FROM triggers
		WHERE kind = $1 AND state = 'active' AND source_workflow_id IS NOT NULL`
	rows, err := j.db.QueryContext(ctx, j.bind(q), string(TriggerWorkflowComplete))
	if err != nil {
		return nil, fmt.Errorf("journal: load chain edges: %w", err)
	}
	defer rows.Close()
	var edges []chainEdge
	for rows.Next() {
		var downstream, source string
		if err := rows.Scan(&downstream, &source); err != nil {
			return nil, err
		}
		edges = append(edges, chainEdge{source: source, downstream: downstream})
	}
	return edges, rows.Err()
}

// chainWouldCycle reports whether adding the edge source -> downstream
// would close a cycle, i.e. whether downstream can already reach source
// by following existing chain edges. BFS over the operator-bounded edge
// set.
func (j *Journal) chainWouldCycle(ctx context.Context, source, downstream string) (bool, error) {
	edges, err := j.allChainEdges(ctx)
	if err != nil {
		return false, err
	}
	adj := map[string][]string{}
	for _, e := range edges {
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

// ChainTriggersForSource returns the downstream triggers that should
// fire when sourceWorkflowID terminated with status. The chain config
// CSV is checked here so the dispatcher does not need to re-parse.
func (j *Journal) ChainTriggersForSource(ctx context.Context, sourceWorkflowID, status string) ([]Trigger, error) {
	// Filter on the indexed source_workflow_id column instead of scanning
	// every workflow_complete trigger and parsing the source out of JSON.
	const q = `SELECT id, tenant_id, workflow_id, kind, config_json, state, token_id, secret_id, provider, last_fired_at, last_error, created_at, updated_at
		FROM triggers
		WHERE kind = $1 AND state = 'active' AND source_workflow_id = $2`
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
	OnStatuses           string
}

func (j *Journal) ChainTriggersDownstreamOf(ctx context.Context, sourceWorkflowID string) ([]ChainTriggerView, error) {
	const q = `SELECT t.id, t.workflow_id, w.slug, t.config_json
		FROM triggers t JOIN workflows w ON w.id = t.workflow_id
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
		if err := rows.Scan(&row.TriggerID, &row.DownstreamWorkflowID, &row.DownstreamSlug, &cfgBytes); err != nil {
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
	const q = `SELECT id, workflow_id, config_json FROM triggers
		WHERE kind = $1 AND workflow_id = $2 AND state = 'active'`
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
