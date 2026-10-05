package journal

import (
	"context"
	"fmt"
	"strings"
)

// HasActiveCommandAutomationTriggerForTenant reports whether a tenant has at
// least one active command schedule, webhook, or terminal-chain binding for an
// enabled plan. It is intentionally an existence query: readiness must not
// load trigger definitions or command text, and a restored tenant with a large
// trigger inventory must remain cheap to probe.
//
// The enabled-plan predicate mirrors the runtime drivers. A disabled plan may
// retain an active trigger as a durable operator configuration, but it cannot
// fire until the plan is enabled again, so it should not withdraw daemon
// readiness by itself. The caller uses this only when the command runner is
// unavailable; ordinary command admission errors remain per-trigger receipts.
func (j *Journal) HasActiveCommandAutomationTriggerForTenant(ctx context.Context, tenantID string) (bool, error) {
	if j == nil || j.db == nil {
		return false, fmt.Errorf("journal: database is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = DefaultTenant
	}
	trueLiteral := "true"
	if j.engine == EngineSQLite {
		trueLiteral = "1"
	}
	q := `SELECT EXISTS (
		SELECT 1
		FROM command_automation_schedules s
		JOIN command_automations a ON a.id = s.automation_id AND a.tenant_id = s.tenant_id
		WHERE s.tenant_id = $1 AND s.state = 'active' AND a.enabled = ` + trueLiteral + `
		UNION ALL
		SELECT 1
		FROM command_automation_webhook_triggers w
		JOIN command_automations a ON a.id = w.automation_id AND a.tenant_id = w.tenant_id
		WHERE w.tenant_id = $2 AND w.state = 'active' AND a.enabled = ` + trueLiteral + `
		UNION ALL
		SELECT 1
		FROM command_automation_chain_triggers c
		JOIN command_automations a ON a.id = c.automation_id AND a.tenant_id = c.tenant_id
		WHERE c.tenant_id = $3 AND c.state = 'active' AND a.enabled = ` + trueLiteral + `
	)`
	var active bool
	if err := j.db.QueryRowContext(ctx, j.bind(q), tenantID, tenantID, tenantID).Scan(&active); err != nil {
		return false, fmt.Errorf("journal: inspect active command automation triggers: %w", err)
	}
	return active, nil
}
