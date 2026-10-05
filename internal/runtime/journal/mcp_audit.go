package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MCPAuditEntry is the redacted control-plane receipt for one MCP mutation or
// explicitly scoped exact/bulk data read.
// It deliberately carries target metadata rather than the request payload:
// payloads can contain customer data, source code, or operator input.
type MCPAuditEntry struct {
	ID       string          `json:"id"`
	TenantID string          `json:"tenant_id"`
	ActorID  string          `json:"actor_id,omitempty"`
	ToolName string          `json:"tool_name"`
	Outcome  string          `json:"outcome"`
	Target   string          `json:"target,omitempty"`
	Detail   json.RawMessage `json:"detail,omitempty"`
	At       time.Time       `json:"at"`
}

// AppendMCPAudit writes one bounded, redacted MCP control-plane receipt.
func (j *Journal) AppendMCPAudit(ctx context.Context, entry MCPAuditEntry) error {
	if entry.TenantID == "" {
		entry.TenantID = DefaultTenant
	}
	if entry.ToolName == "" || len(entry.ToolName) > 128 {
		return errors.New("journal: mcp audit tool_name is required and must be <=128 bytes")
	}
	if entry.Outcome != "succeeded" && entry.Outcome != "failed" {
		return fmt.Errorf("journal: mcp audit unsupported outcome %q", entry.Outcome)
	}
	if len(entry.Target) > 512 {
		return errors.New("journal: mcp audit target exceeds 512 bytes")
	}
	if len(entry.Detail) == 0 {
		entry.Detail = json.RawMessage(`{}`)
	}
	if len(entry.Detail) > 4096 || !json.Valid(entry.Detail) {
		return errors.New("journal: mcp audit detail must be valid JSON <=4096 bytes")
	}
	if entry.ActorID == "" {
		entry.ActorID = "mcp"
	}
	if entry.ID == "" {
		id, err := newID("mcpaudit_")
		if err != nil {
			return err
		}
		entry.ID = id
	}
	const q = `INSERT INTO mcp_audit
		(id, tenant_id, actor_id, tool_name, outcome, target, detail, at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := j.db.ExecContext(ctx, j.bind(q), entry.ID, entry.TenantID, entry.ActorID,
		entry.ToolName, entry.Outcome, entry.Target, outputArg(entry.Detail, j.engine), j.now())
	if err != nil {
		return fmt.Errorf("journal: append mcp audit: %w", err)
	}
	return nil
}

// ListMCPAuditForTenant returns newest-first redacted MCP receipts.
func (j *Journal) ListMCPAuditForTenant(ctx context.Context, tenantID string, limit, offset int) ([]MCPAuditEntry, error) {
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		return nil, errors.New("journal: list mcp audit offset must be non-negative")
	}
	const q = `SELECT id, tenant_id, actor_id, tool_name, outcome, target, detail, at
		FROM mcp_audit WHERE tenant_id = $1
		ORDER BY at DESC, id DESC LIMIT $2 OFFSET $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list mcp audit: %w", err)
	}
	defer rows.Close()
	var out []MCPAuditEntry
	for rows.Next() {
		var (
			entry  MCPAuditEntry
			detail []byte
			at     sql.NullString
		)
		if err := rows.Scan(&entry.ID, &entry.TenantID, &entry.ActorID, &entry.ToolName, &entry.Outcome, &entry.Target, &detail, &at); err != nil {
			return nil, fmt.Errorf("journal: scan mcp audit: %w", err)
		}
		if len(detail) > 0 {
			entry.Detail = json.RawMessage(detail)
		}
		if at.Valid {
			if parsed, err := j.parseTime(at.String); err == nil {
				entry.At = parsed
			}
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate mcp audit: %w", err)
	}
	return out, nil
}

// ListMCPAuditForTenantPage is the lookahead variant used by bounded MCP
// responses. It returns up to limit rows plus one continuation row.
func (j *Journal) ListMCPAuditForTenantPage(ctx context.Context, tenantID string, limit, offset int) ([]MCPAuditEntry, error) {
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	if offset < 0 {
		return nil, errors.New("journal: list mcp audit offset must be non-negative")
	}
	const q = `SELECT id, tenant_id, actor_id, tool_name, outcome, target, detail, at
		FROM mcp_audit WHERE tenant_id = $1
		ORDER BY at DESC, id DESC LIMIT $2 OFFSET $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("journal: list mcp audit page: %w", err)
	}
	defer rows.Close()
	var out []MCPAuditEntry
	for rows.Next() {
		var (
			entry  MCPAuditEntry
			detail []byte
			at     sql.NullString
		)
		if err := rows.Scan(&entry.ID, &entry.TenantID, &entry.ActorID, &entry.ToolName, &entry.Outcome, &entry.Target, &detail, &at); err != nil {
			return nil, fmt.Errorf("journal: scan mcp audit page: %w", err)
		}
		if len(detail) > 0 {
			entry.Detail = json.RawMessage(detail)
		}
		if at.Valid {
			if parsed, err := j.parseTime(at.String); err == nil {
				entry.At = parsed
			}
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate mcp audit page: %w", err)
	}
	return out, nil
}
