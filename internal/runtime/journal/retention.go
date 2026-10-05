package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrTenantErasureActive prevents a data erasure from racing an in-flight
// execution. The caller must drain or cancel these runs before retrying.
var ErrTenantErasureActive = errors.New("journal: tenant erasure blocked by active runs")

// This file is the GDPR/data-retention surface: an opt-in purge of old run
// history, plus per-tenant data export (portability) and erasure.

// terminalRunPredicate matches finished runs (not running/suspended/queued)
// older than the bound parameter. COALESCE(finished_at, created_at) so a run
// that finished without a finished_at still ages out by creation time.
// An admitted connected-mail intent without a resolution is an unresolved
// provider write. Keep its run and receipt regardless of run age; a recorded
// operator resolution restores normal retention eligibility.
const terminalRunPredicate = `status NOT IN ('running','suspended','queued') AND COALESCE(finished_at, created_at) < $1
	AND NOT EXISTS (SELECT 1 FROM mail_send_intents m WHERE m.run_id = runs.id AND m.status = 'admitted'
		AND NOT EXISTS (SELECT 1 FROM mail_send_resolutions x WHERE x.intent_id = m.id))`

// commandRunTerminalPredicate intentionally names the terminal states instead
// of using a broad NOT IN expression. Command-run statuses are a separate
// state machine; an imported or future non-terminal state must not be
// silently destroyed by retention.
const commandRunTerminalPredicate = `status IN ('succeeded','failed','cancelled') AND COALESCE(finished_at, created_at) < $1`

const (
	defaultTenantExportCommandRunLimit  = 25
	defaultTenantExportCommandStepLimit = 25
	maxTenantExportCommandOutputBytes   = 16 << 10
	maxTenantExportCommandErrorBytes    = 4 << 10
	maxTenantExportCommandStepCells     = 2000
	retentionBatchSize                  = 128
	retentionMaxBatchesPerTick          = 16
	// A distinct PostgreSQL transaction advisory lock serializes retention
	// batches across serve replicas ("REACTRET"). Parent/child and retry
	// detachment can otherwise deadlock when two batches select related runs.
	retentionBatchLockKey int64 = 0x5245414354524554
)

// PurgeTerminalRunsOlderThan deletes finished workflow runs and terminal
// command runs (and their steps, attempts, leases, schedules, logs via
// cascade; dead_letter + parent refs handled explicitly) older than cutoff.
// run_usage is intentionally kept (billing aggregates, no run payloads).
// Each call removes at most retentionBatchSize runs of each kind per committed
// transaction, for at most retentionMaxBatchesPerTick transactions. A later
// call resumes any backlog. Returns the combined number of workflow and
// command runs actually removed, including committed batches before an error.
// Off unless an operator sets a retention period.
func (j *Journal) PurgeTerminalRunsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	return j.purgeTerminalRunsOlderThan(ctx, cutoff, retentionBatchSize, retentionMaxBatchesPerTick)
}

func (j *Journal) purgeTerminalRunsOlderThan(ctx context.Context, cutoff time.Time, batchSize, maxBatches int) (int64, error) {
	if batchSize < 1 || batchSize > 512 || maxBatches < 1 {
		return 0, errors.New("journal: invalid retention batch limits")
	}
	var removed int64
	for i := 0; i < maxBatches; i++ {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		n, full, err := j.purgeTerminalRunsBatch(ctx, cutoff, batchSize)
		removed += n
		if err != nil {
			return removed, err
		}
		if !full {
			break
		}
	}
	return removed, nil
}

// purgeTerminalRunsBatch commits the workflow and command candidates as one
// bounded unit. Row locks keep a concurrent Postgres daemon from choosing the
// same parents; SQLite takes its single-writer lock before reading candidates.
func (j *Journal) purgeTerminalRunsBatch(ctx context.Context, cutoff time.Time, batchSize int) (int64, bool, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	if j.engine == EnginePostgres {
		var locked bool
		if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1)`, retentionBatchLockKey).Scan(&locked); err != nil {
			return 0, false, fmt.Errorf("journal: lock retention batch: %w", err)
		}
		if !locked {
			// Another replica owns this batch window. Its transaction will
			// commit or roll back independently; the next minute resumes.
			return 0, false, nil
		}
	} else if j.engine == EngineSQLite {
		// A deferred SQLite transaction could otherwise read candidates before
		// another writer commits, then fail upgrading its read snapshot to a
		// writer. The schema row exists on every migrated database.
		if _, err := tx.ExecContext(ctx, `UPDATE schema_meta SET value = value WHERE key = 'engine'`); err != nil {
			return 0, false, fmt.Errorf("journal: lock retention writer: %w", err)
		}
	}
	cut := j.formatTime(cutoff.UTC())
	runIDs, err := j.retentionCandidates(ctx, tx, "runs", terminalRunPredicate, "runs_terminal_retention_idx", cut, batchSize)
	if err != nil {
		return 0, false, fmt.Errorf("journal: select terminal runs: %w", err)
	}
	commandIDs, err := j.retentionCandidates(ctx, tx, "command_runs", commandRunTerminalPredicate, "command_runs_terminal_retention_idx", cut, batchSize)
	if err != nil {
		return 0, false, fmt.Errorf("journal: select terminal command runs: %w", err)
	}
	if len(runIDs) == 0 && len(commandIDs) == 0 {
		return 0, false, nil
	}
	var removed int64
	if len(runIDs) > 0 {
		target, args := retentionIDList(runIDs)

		// Detach survivors whose parent is being deleted (parent_run_id has no
		// cascade), then remove dead_letter (no cascade) before deleting runs.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET parent_run_id = NULL WHERE parent_run_id IN `+target), args...); err != nil {
			return 0, false, fmt.Errorf("journal: purge detach children: %w", err)
		}
		if j.engine == EngineSQLite {
			// Production SQLite handles enable FKs, but older/raw handles may
			// not. Delete every run-bound payload table explicitly in dependency
			// order so those handles do not retain orphaned history.
			for _, table := range []string{"mail_send_resolutions", "mail_send_intents", "run_block_receipts", "steps", "leases", "schedules", "run_logs", "terminal_effects"} {
				if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM `+table+` WHERE run_id IN `+target), args...); err != nil {
					return 0, false, fmt.Errorf("journal: purge %s: %w", table, err)
				}
			}
		}
		if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM dead_letter WHERE run_id IN `+target), args...); err != nil {
			return 0, false, fmt.Errorf("journal: purge dead_letter: %w", err)
		}
		// Legacy/raw SQLite handles may omit the foreign-key pragma. Explicitly
		// delete audit references even in that case.
		if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM runtime_secret_access_audit WHERE run_id IN `+target), args...); err != nil {
			return 0, false, fmt.Errorf("journal: purge runtime secret audit: %w", err)
		}
		res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM runs WHERE id IN `+target), args...)
		if err != nil {
			return 0, false, fmt.Errorf("journal: purge runs: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	if len(commandIDs) > 0 {
		target, args := retentionIDList(commandIDs)
		// Retry lineage is metadata rather than an FK. A surviving retry
		// remains independently inspectable after its source is removed.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_runs SET retry_of = NULL WHERE retry_of IN `+target), args...); err != nil {
			return 0, false, fmt.Errorf("journal: purge detach command retries: %w", err)
		}
		if j.engine == EngineSQLite {
			for _, table := range []string{"command_run_step_attempts", "command_run_steps"} {
				if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM `+table+` WHERE run_id IN `+target), args...); err != nil {
					return 0, false, fmt.Errorf("journal: purge %s: %w", table, err)
				}
			}
		}
		res, err := tx.ExecContext(ctx, j.bind(`DELETE FROM command_runs WHERE id IN `+target), args...)
		if err != nil {
			return 0, false, fmt.Errorf("journal: purge command runs: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return removed, len(runIDs) == batchSize || len(commandIDs) == batchSize, nil
}

func (j *Journal) retentionCandidates(ctx context.Context, tx *sql.Tx, table, predicate, index string, cutoff any, limit int) ([]string, error) {
	// The table/predicate/index arguments are fixed package constants, never
	// input. SQLite's planner can otherwise choose command_runs_lease_idx for
	// the status filter and sort the entire eligible history each batch.
	if j.engine == EngineSQLite {
		table += ` INDEXED BY ` + index
	}
	q := `SELECT id FROM ` + table + ` WHERE ` + predicate +
		` ORDER BY COALESCE(finished_at, created_at), id LIMIT $2`
	if j.engine == EnginePostgres {
		q += ` FOR UPDATE SKIP LOCKED`
	}
	rows, err := tx.QueryContext(ctx, j.bind(q), cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func retentionIDList(ids []string) (string, []any) {
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	return `(` + strings.Join(placeholders, ",") + `)`, args
}

// TenantExport is a tenant's portable data snapshot (GDPR data portability).
type TenantExport struct {
	TenantID           string                    `json:"tenant_id"`
	Tenant             Tenant                    `json:"tenant"`
	Workflows          []Workflow                `json:"workflows"`
	CommandAutomations []CommandAutomationExport `json:"command_automations"`
	CommandRuns        []CommandRunExport        `json:"command_runs"`
	Runs               []RunInfo                 `json:"runs"`
	Usage              TenantUsage               `json:"usage_to_date"`
}

// CommandRunExport is the portable, non-executable projection of one command
// run. Step command text is never included; command_sha256, status, exit code,
// and bounded redacted output are sufficient to audit a run without turning an
// export into a process-launch or secret-disclosure surface.
type CommandRunExport struct {
	Run            CommandRun       `json:"run"`
	Steps          []CommandRunStep `json:"steps"`
	StepsHasMore   bool             `json:"steps_has_more,omitempty"`
	NextStepOffset int              `json:"next_step_offset,omitempty"`
}

// CommandAutomationExport keeps plan metadata and every immutable definition
// together so a tenant can review or restore its declarative plans without
// exposing vault values.
type CommandAutomationExport struct {
	Automation CommandAutomation          `json:"automation"`
	Versions   []CommandAutomationVersion `json:"versions"`
}

// TenantExportPageOptions controls the bounded MCP portability snapshot.
// Every offset/limit applies to one independent section of the export. The
// command version page is applied to each returned plan so a caller can walk
// immutable definitions without ever asking the journal to load all history.
type TenantExportPageOptions struct {
	WorkflowLimit           int
	WorkflowOffset          int
	CommandAutomationLimit  int
	CommandAutomationOffset int
	CommandVersionLimit     int
	CommandVersionOffset    int
	RunLimit                int
	RunOffset               int
	CommandRunLimit         int
	CommandRunOffset        int
	CommandStepLimit        int
	CommandStepOffset       int
}

// CommandAutomationExportPage is the bounded form used by MCP portability.
// Version continuation is explicit because definitions are untrusted data and
// can be close to the per-definition storage cap.
type CommandAutomationExportPage struct {
	Automation        CommandAutomation          `json:"automation"`
	Versions          []CommandAutomationVersion `json:"versions"`
	VersionsHasMore   bool                       `json:"versions_has_more"`
	NextVersionOffset int                        `json:"next_version_offset,omitempty"`
}

// TenantExportPage is a bounded, tenant-scoped portability snapshot. A true
// section HasMore flag means the response is intentionally incomplete and the
// caller must advance that section's offset before treating the export as
// complete.
type TenantExportPage struct {
	TenantID                    string                        `json:"tenant_id"`
	Tenant                      Tenant                        `json:"tenant"`
	Workflows                   []Workflow                    `json:"workflows"`
	WorkflowsHasMore            bool                          `json:"workflows_has_more"`
	NextWorkflowOffset          int                           `json:"next_workflow_offset,omitempty"`
	CommandAutomations          []CommandAutomationExportPage `json:"command_automations"`
	CommandAutomationsHasMore   bool                          `json:"command_automations_has_more"`
	NextCommandAutomationOffset int                           `json:"next_command_automation_offset,omitempty"`
	CommandRuns                 []CommandRunExport            `json:"command_runs"`
	CommandRunsHasMore          bool                          `json:"command_runs_has_more"`
	NextCommandRunOffset        int                           `json:"next_command_run_offset,omitempty"`
	Runs                        []RunInfo                     `json:"runs"`
	RunsHasMore                 bool                          `json:"runs_has_more"`
	NextRunOffset               int                           `json:"next_run_offset,omitempty"`
	Usage                       TenantUsage                   `json:"usage_to_date"`
}

// ExportTenantDataPage gathers one bounded page from each portable section.
// It is deliberately separate from ExportTenantData, whose historical API
// keeps its all-configuration semantics for local/offline callers.
func (j *Journal) ExportTenantDataPage(ctx context.Context, tenantID string, opts TenantExportPageOptions) (TenantExportPage, error) {
	if opts.CommandRunLimit == 0 {
		opts.CommandRunLimit = defaultTenantExportCommandRunLimit
	}
	if opts.CommandStepLimit == 0 {
		opts.CommandStepLimit = defaultTenantExportCommandStepLimit
	}
	if opts.WorkflowLimit <= 0 || opts.WorkflowLimit > 500 || opts.WorkflowOffset < 0 ||
		opts.CommandAutomationLimit <= 0 || opts.CommandAutomationLimit > 500 || opts.CommandAutomationOffset < 0 ||
		opts.CommandVersionLimit <= 0 || opts.CommandVersionLimit > 500 || opts.CommandVersionOffset < 0 ||
		opts.RunLimit <= 0 || opts.RunLimit > 1000 || opts.RunOffset < 0 ||
		opts.CommandRunLimit <= 0 || opts.CommandRunLimit > 500 || opts.CommandRunOffset < 0 ||
		opts.CommandStepLimit <= 0 || opts.CommandStepLimit > 500 || opts.CommandStepOffset < 0 {
		return TenantExportPage{}, errors.New("journal: invalid tenant export page")
	}
	if opts.CommandRunLimit > maxTenantExportCommandStepCells/opts.CommandStepLimit {
		return TenantExportPage{}, errors.New("journal: command-run export page is too large")
	}
	exp := TenantExportPage{TenantID: tenantID}
	if t, err := j.GetTenant(ctx, tenantID); err == nil {
		exp.Tenant = t
	}
	workflows, more, err := j.ListWorkflowsByTenantPage(ctx, tenantID, opts.WorkflowLimit, opts.WorkflowOffset)
	if err != nil {
		return TenantExportPage{}, err
	}
	exp.Workflows, exp.WorkflowsHasMore = workflows, more
	if more {
		exp.NextWorkflowOffset = opts.WorkflowOffset + len(workflows)
	}
	plans, more, err := j.ListCommandAutomationsPage(ctx, tenantID, opts.CommandAutomationLimit, opts.CommandAutomationOffset)
	if err != nil {
		return TenantExportPage{}, err
	}
	exp.CommandAutomations = make([]CommandAutomationExportPage, 0, len(plans))
	for _, plan := range plans {
		versions, versionsMore, versionErr := j.ListCommandAutomationVersionsPage(ctx, tenantID, plan.ID, opts.CommandVersionLimit, opts.CommandVersionOffset)
		if versionErr != nil {
			return TenantExportPage{}, versionErr
		}
		page := CommandAutomationExportPage{Automation: plan, Versions: versions, VersionsHasMore: versionsMore}
		if versionsMore {
			page.NextVersionOffset = opts.CommandVersionOffset + len(versions)
		}
		exp.CommandAutomations = append(exp.CommandAutomations, page)
	}
	exp.CommandAutomationsHasMore = more
	if more {
		exp.NextCommandAutomationOffset = opts.CommandAutomationOffset + len(plans)
	}
	commandRuns, err := j.ListCommandRunsForTenantPage(ctx, CommandRunFilter{
		TenantID: tenantID, Limit: opts.CommandRunLimit + 1, Offset: opts.CommandRunOffset,
	})
	if err != nil {
		return TenantExportPage{}, err
	}
	exp.CommandRunsHasMore = len(commandRuns) > opts.CommandRunLimit
	if exp.CommandRunsHasMore {
		commandRuns = commandRuns[:opts.CommandRunLimit]
		exp.NextCommandRunOffset = opts.CommandRunOffset + len(commandRuns)
	}
	exp.CommandRuns = make([]CommandRunExport, 0, len(commandRuns))
	for _, run := range commandRuns {
		steps, stepErr := j.ListCommandRunStepsPageForTenantBounded(ctx, tenantID, run.ID,
			opts.CommandStepLimit+1, opts.CommandStepOffset,
			maxTenantExportCommandOutputBytes, maxTenantExportCommandErrorBytes)
		if stepErr != nil {
			return TenantExportPage{}, stepErr
		}
		stepsMore := len(steps) > opts.CommandStepLimit
		if stepsMore {
			steps = steps[:opts.CommandStepLimit]
		}
		page := CommandRunExport{Run: run, Steps: steps, StepsHasMore: stepsMore}
		if stepsMore {
			page.NextStepOffset = opts.CommandStepOffset + len(steps)
		}
		exp.CommandRuns = append(exp.CommandRuns, page)
	}
	runs, err := j.ListRuns(ctx, RunFilter{TenantID: tenantID, Limit: opts.RunLimit + 1, Offset: opts.RunOffset})
	if err != nil {
		return TenantExportPage{}, err
	}
	exp.RunsHasMore = len(runs) > opts.RunLimit
	if exp.RunsHasMore {
		runs = runs[:opts.RunLimit]
		exp.NextRunOffset = opts.RunOffset + len(runs)
	}
	exp.Runs = runs
	usage, err := j.TenantUsageSince(ctx, tenantID, time.Time{})
	if err != nil {
		return TenantExportPage{}, fmt.Errorf("journal: export tenant usage: %w", err)
	}
	exp.Usage = usage
	return exp, nil
}

// ExportTenantData gathers a tenant's data for export. Runs are capped at
// maxRuns (newest first) to keep the payload bounded.
func (j *Journal) ExportTenantData(ctx context.Context, tenantID string, maxRuns int) (TenantExport, error) {
	if maxRuns <= 0 {
		maxRuns = 1000
	}
	exp := TenantExport{TenantID: tenantID}
	if t, err := j.GetTenant(ctx, tenantID); err == nil {
		exp.Tenant = t
	}
	wfs, err := j.ListWorkflowsByTenant(ctx, tenantID)
	if err != nil {
		return TenantExport{}, err
	}
	exp.Workflows = wfs
	exp.CommandAutomations = make([]CommandAutomationExport, 0)
	for offset := 0; ; {
		commandPlans, more, err := j.ListCommandAutomationsPage(ctx, tenantID, 500, offset)
		if err != nil {
			return TenantExport{}, err
		}
		for _, plan := range commandPlans {
			versions, err := j.ListCommandAutomationVersions(ctx, tenantID, plan.ID)
			if err != nil {
				return TenantExport{}, err
			}
			exp.CommandAutomations = append(exp.CommandAutomations, CommandAutomationExport{Automation: plan, Versions: versions})
		}
		if !more {
			break
		}
		offset += len(commandPlans)
	}
	commandRunLimit := maxRuns
	if commandRunLimit > 1000 {
		commandRunLimit = 1000
	}
	commandRuns, err := j.ListCommandRunsForTenantPage(ctx, CommandRunFilter{TenantID: tenantID, Limit: commandRunLimit, Offset: 0})
	if err != nil {
		return TenantExport{}, err
	}
	exp.CommandRuns = make([]CommandRunExport, 0, len(commandRuns))
	for _, run := range commandRuns {
		steps, stepErr := j.ListCommandRunStepsPageForTenantBounded(ctx, tenantID, run.ID, defaultTenantExportCommandStepLimit, 0, maxTenantExportCommandOutputBytes, maxTenantExportCommandErrorBytes)
		if stepErr != nil {
			return TenantExport{}, stepErr
		}
		exp.CommandRuns = append(exp.CommandRuns, CommandRunExport{Run: run, Steps: steps})
	}
	runs, err := j.ListRuns(ctx, RunFilter{TenantID: tenantID, Limit: maxRuns})
	if err != nil {
		return TenantExport{}, err
	}
	exp.Runs = runs
	usage, err := j.TenantUsageSince(ctx, tenantID, time.Time{})
	if err != nil {
		return TenantExport{}, fmt.Errorf("journal: export tenant usage: %w", err)
	}
	exp.Usage = usage
	return exp, nil
}

// TenantErasure reports what an erase removed.
type TenantErasure struct {
	Runs        int64 `json:"runs"`
	CommandRuns int64 `json:"command_runs"`
	DeadLetters int64 `json:"dead_letters"`
	Usage       int64 `json:"usage_rows"`
}

// TenantErasurePreview is a read-only impact receipt for the destructive
// tenant run-history erasure. It intentionally excludes workflow and secret
// configuration, which the erasure does not touch.
type TenantErasurePreview struct {
	TenantID          string `json:"tenant_id"`
	Runs              int64  `json:"runs"`
	ActiveRuns        int64  `json:"active_runs"`
	CommandRuns       int64  `json:"command_runs"`
	ActiveCommandRuns int64  `json:"active_command_runs"`
	DeadLetters       int64  `json:"dead_letters"`
	Usage             int64  `json:"usage_rows"`
	Erasable          bool   `json:"erasable"`
}

// PreviewTenantErasure returns a consistent, tenant-scoped impact snapshot.
// It never mutates rows and remains useful to read-only MCP clients before the
// explicitly scoped erase tool is enabled.
func (j *Journal) PreviewTenantErasure(ctx context.Context, tenantID string) (TenantErasurePreview, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantErasurePreview{}, err
	}
	defer tx.Rollback()
	preview := TenantErasurePreview{TenantID: tenantID}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE tenant_id = $1`), tenantID).Scan(&preview.Runs); err != nil {
		return TenantErasurePreview{}, fmt.Errorf("journal: preview tenant runs: %w", err)
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status IN ('running','queued','suspended')`), tenantID).Scan(&preview.ActiveRuns); err != nil {
		return TenantErasurePreview{}, fmt.Errorf("journal: preview tenant active runs: %w", err)
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM command_runs WHERE tenant_id = $1`), tenantID).Scan(&preview.CommandRuns); err != nil {
		return TenantErasurePreview{}, fmt.Errorf("journal: preview tenant command runs: %w", err)
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM command_runs WHERE tenant_id = $1 AND status NOT IN ('succeeded','failed','cancelled')`), tenantID).Scan(&preview.ActiveCommandRuns); err != nil {
		return TenantErasurePreview{}, fmt.Errorf("journal: preview tenant active command runs: %w", err)
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM dead_letter d JOIN runs r ON r.id = d.run_id WHERE r.tenant_id = $1`), tenantID).Scan(&preview.DeadLetters); err != nil {
		return TenantErasurePreview{}, fmt.Errorf("journal: preview tenant dead letters: %w", err)
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM run_usage WHERE tenant_id = $1`), tenantID).Scan(&preview.Usage); err != nil {
		return TenantErasurePreview{}, fmt.Errorf("journal: preview tenant usage: %w", err)
	}
	preview.Erasable = preview.ActiveRuns == 0 && preview.ActiveCommandRuns == 0
	return preview, nil
}

// EraseTenantData deletes a tenant's run history + usage ledger (GDPR right to
// erasure). Workflows, credentials, and connections are left in place (they are
// the tenant's configuration, not personal run data); delete the tenant +
// those separately to fully offboard. Returns the counts removed.
func (j *Journal) EraseTenantData(ctx context.Context, tenantID string) (TenantErasure, error) {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantErasure{}, err
	}
	defer tx.Rollback()
	// Live dispatch locks its workflow row before inserting a run. Take those
	// same locks before counting active runs, so an admitted run either commits
	// first and blocks erasure, or starts only after this erasure has committed.
	// This does not pause retained workflow definitions: a later event starts a
	// new run and belongs to the post-erasure history.
	if j.engine == EnginePostgres {
		rows, err := tx.QueryContext(ctx, j.bind(`SELECT id FROM workflows WHERE tenant_id = $1 ORDER BY id FOR UPDATE`), tenantID)
		if err != nil {
			return TenantErasure{}, fmt.Errorf("journal: erase lock tenant workflows: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return TenantErasure{}, fmt.Errorf("journal: erase scan locked workflow: %w", err)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return TenantErasure{}, fmt.Errorf("journal: erase iterate locked workflows: %w", err)
		}
		if err := rows.Close(); err != nil {
			return TenantErasure{}, fmt.Errorf("journal: erase close locked workflows: %w", err)
		}
	} else {
		// SQLite's writer lock gives the same ordering for every workflow
		// admission, including an empty tenant's first later run.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE workflows SET updated_at = updated_at WHERE tenant_id = $1`), tenantID); err != nil {
			return TenantErasure{}, fmt.Errorf("journal: erase lock tenant workflows: %w", err)
		}
	}
	// Command-run admission locks the command-automation row. Take the same
	// lock before counting/deleting command runs so a concurrent admission is
	// ordered either before the erase (and blocks it as active) or after the
	// committed erase. This is independent of workflow rows.
	if j.engine == EnginePostgres {
		rows, err := tx.QueryContext(ctx, j.bind(`SELECT id FROM command_automations WHERE tenant_id = $1 ORDER BY id FOR UPDATE`), tenantID)
		if err != nil {
			return TenantErasure{}, fmt.Errorf("journal: erase lock command automations: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return TenantErasure{}, fmt.Errorf("journal: erase scan locked command automation: %w", err)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return TenantErasure{}, fmt.Errorf("journal: erase iterate locked command automations: %w", err)
		}
		if err := rows.Close(); err != nil {
			return TenantErasure{}, fmt.Errorf("journal: erase close locked command automations: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE command_automations SET current_version = current_version WHERE tenant_id = $1`), tenantID); err != nil {
			return TenantErasure{}, fmt.Errorf("journal: erase lock command automations: %w", err)
		}
	}
	var active int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM runs WHERE tenant_id = $1 AND status IN ('running','queued','suspended')`), tenantID).Scan(&active); err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase active-run check: %w", err)
	}
	if active > 0 {
		return TenantErasure{}, fmt.Errorf("%w: %d run(s) still active", ErrTenantErasureActive, active)
	}
	var activeCommand int
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM command_runs WHERE tenant_id = $1 AND status NOT IN ('succeeded','failed','cancelled')`), tenantID).Scan(&activeCommand); err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase active command-run check: %w", err)
	}
	if activeCommand > 0 {
		return TenantErasure{}, fmt.Errorf("%w: %d command run(s) still active", ErrTenantErasureActive, activeCommand)
	}
	target := `(SELECT id FROM runs WHERE tenant_id = $1)`
	if _, err := tx.ExecContext(ctx, j.bind(`UPDATE runs SET parent_run_id = NULL WHERE parent_run_id IN `+target), tenantID); err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase detach children: %w", err)
	}
	deadLetterRes, err := tx.ExecContext(ctx, j.bind(`DELETE FROM dead_letter WHERE run_id IN `+target), tenantID)
	if err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase dead_letter: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM runtime_secret_access_audit WHERE run_id IN `+target), tenantID); err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase runtime secret audit: %w", err)
	}
	// Raw SQLite handles may not enforce ON DELETE CASCADE. Erasure must not
	// leave behind provider-write receipts after removing the owning runs.
	if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM mail_send_resolutions WHERE run_id IN `+target), tenantID); err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase mail send resolutions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM mail_send_intents WHERE run_id IN `+target), tenantID); err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase mail send intents: %w", err)
	}
	runRes, err := tx.ExecContext(ctx, j.bind(`DELETE FROM runs WHERE tenant_id = $1`), tenantID)
	if err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase runs: %w", err)
	}
	commandRunRes, err := tx.ExecContext(ctx, j.bind(`DELETE FROM command_runs WHERE tenant_id = $1`), tenantID)
	if err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase command runs: %w", err)
	}
	usageRes, err := tx.ExecContext(ctx, j.bind(`DELETE FROM run_usage WHERE tenant_id = $1`), tenantID)
	if err != nil {
		return TenantErasure{}, fmt.Errorf("journal: erase usage: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return TenantErasure{}, err
	}
	var e TenantErasure
	e.Runs, _ = runRes.RowsAffected()
	e.CommandRuns, _ = commandRunRes.RowsAffected()
	e.DeadLetters, _ = deadLetterRes.RowsAffected()
	e.Usage, _ = usageRes.RowsAffected()
	return e, nil
}
