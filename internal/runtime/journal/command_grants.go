package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CommandGrant is one explicit credential grant for a command automation.
// Command plans use a separate ACL from workflow_secret_grants because the
// command runner has a different identity, lifecycle, and admission boundary.
// CredentialID may be a vault credential id or an OAuth connection id in the
// "oauth:<id>" namespace.
type CommandGrant struct {
	AutomationID string    `json:"automation_id"`
	TenantID     string    `json:"tenant_id"`
	CredentialID string    `json:"credential_id"`
	GrantedAt    time.Time `json:"granted_at"`
	GrantedBy    string    `json:"granted_by,omitempty"`
	Note         string    `json:"note,omitempty"`
}

// GrantCommandSecret authorizes one command automation to read one live
// credential. Both resources must exist and belong to tenantID; an empty ACL
// never enables access implicitly. Repeated grants update only the operator
// metadata and retain the original grant timestamp.
func (j *Journal) GrantCommandSecret(ctx context.Context, tenantID, automationID, credentialID, grantedBy, note string) error {
	tenantID = normalizeCommandGrantTenant(tenantID)
	automation, credentialTenant, err := j.resolveCommandGrantTargets(ctx, tenantID, automationID, credentialID)
	if err != nil {
		return err
	}
	if automation.TenantID != credentialTenant {
		return fmt.Errorf("journal: command grant refused: automation tenant %q != credential tenant %q (cross-tenant grants are not allowed)", automation.TenantID, credentialTenant)
	}
	q := `INSERT INTO command_automation_secret_grants
		(automation_id, tenant_id, credential_id, granted_by, note)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (automation_id, credential_id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			granted_by = EXCLUDED.granted_by,
			note = EXCLUDED.note`
	if j.engine == EngineSQLite {
		q = `INSERT INTO command_automation_secret_grants
			(automation_id, tenant_id, credential_id, granted_by, note)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (automation_id, credential_id) DO UPDATE SET
				tenant_id = excluded.tenant_id,
				granted_by = excluded.granted_by,
				note = excluded.note`
	}
	if _, err := j.db.ExecContext(ctx, j.bind(q), automation.ID, automation.TenantID, credentialID, nullable(grantedBy), nullable(note)); err != nil {
		return fmt.Errorf("journal: grant command secret: %w", err)
	}
	return nil
}

// RevokeCommandSecret removes one command automation credential grant. It
// resolves both resource owners before deleting, so a caller cannot use a
// cross-tenant id pair to remove another tenant's grant.
func (j *Journal) RevokeCommandSecret(ctx context.Context, tenantID, automationID, credentialID string) error {
	tenantID = normalizeCommandGrantTenant(tenantID)
	automation, credentialTenant, err := j.resolveCommandGrantTargets(ctx, tenantID, automationID, credentialID)
	if err != nil {
		return err
	}
	if automation.TenantID != credentialTenant {
		return fmt.Errorf("journal: command revoke refused: automation tenant %q != credential tenant %q", automation.TenantID, credentialTenant)
	}
	const q = `DELETE FROM command_automation_secret_grants
		WHERE automation_id = $1 AND tenant_id = $2 AND credential_id = $3`
	res, err := j.db.ExecContext(ctx, j.bind(q), automation.ID, automation.TenantID, credentialID)
	if err != nil {
		return fmt.Errorf("journal: revoke command secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("journal: revoke command secret rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// HasCommandGrant reports whether a live same-tenant credential is explicitly
// granted to a command automation. Missing automation, missing/deleted
// credential, and cross-tenant pairs all fail closed as (false, nil); callers
// must never interpret an empty table as permissive. Database failures remain
// errors so availability problems cannot be mistaken for a deliberate denial.
func (j *Journal) HasCommandGrant(ctx context.Context, tenantID, automationID, credentialID string) (bool, error) {
	tenantID = normalizeCommandGrantTenant(tenantID)
	automation, credentialTenant, err := j.resolveCommandGrantTargets(ctx, tenantID, automationID, credentialID)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrGrantTarget) {
			return false, nil
		}
		return false, err
	}
	if automation.TenantID != credentialTenant {
		return false, nil
	}
	const q = `SELECT 1 FROM command_automation_secret_grants
		WHERE automation_id = $1 AND tenant_id = $2 AND credential_id = $3 LIMIT 1`
	var ok int
	err = j.db.QueryRowContext(ctx, j.bind(q), automation.ID, automation.TenantID, credentialID).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("journal: has command grant: %w", err)
	}
	return true, nil
}

// ListCommandSecretGrantsPage returns a bounded, tenant-scoped grant page for
// one command automation. The automation and every returned credential are
// rechecked against the tenant, so stale or manually tampered rows cannot
// become an authorization or metadata leak.
func (j *Journal) ListCommandSecretGrantsPage(ctx context.Context, tenantID, automationID string, limit, offset int) ([]CommandGrant, bool, error) {
	tenantID = normalizeCommandGrantTenant(tenantID)
	if strings.TrimSpace(automationID) == "" {
		return nil, false, errors.New("journal: list command grants: automation_id required")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, errors.New("journal: list command grants: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, errors.New("journal: list command grants: negative offset")
	}
	automation, err := j.GetCommandAutomation(ctx, tenantID, automationID)
	if errors.Is(err, ErrNotFound) {
		return nil, false, fmt.Errorf("%w: command automation %q", ErrGrantTarget, automationID)
	}
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command grants: resolve automation: %w", err)
	}
	const q = `SELECT g.automation_id, g.tenant_id, g.credential_id, g.granted_at, g.granted_by, g.note
		FROM command_automation_secret_grants g
		JOIN command_automations a ON a.id = g.automation_id AND a.tenant_id = g.tenant_id
		WHERE g.automation_id = $1 AND g.tenant_id = $2
		  AND (EXISTS (SELECT 1 FROM credentials c
		               WHERE c.id = g.credential_id AND c.tenant_id = g.tenant_id AND c.deleted_at IS NULL)
		       OR EXISTS (SELECT 1 FROM oauth_connections o
		                  WHERE g.credential_id = 'oauth:' || o.id AND o.tenant_id = g.tenant_id))
		ORDER BY g.credential_id LIMIT $3 OFFSET $4`
	rows, err := j.db.QueryContext(ctx, j.bind(q), automation.ID, automation.TenantID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list command grants: %w", err)
	}
	defer rows.Close()
	out := make([]CommandGrant, 0, limit)
	for rows.Next() {
		var (
			grant                            CommandGrant
			grantedAt, grantedByAny, noteAny any
		)
		if err := rows.Scan(&grant.AutomationID, &grant.TenantID, &grant.CredentialID, &grantedAt, &grantedByAny, &noteAny); err != nil {
			return nil, false, fmt.Errorf("journal: scan command grant: %w", err)
		}
		grant.GrantedAt = j.anyTime(grantedAt)
		grant.GrantedBy = anyToString(grantedByAny)
		grant.Note = anyToString(noteAny)
		out = append(out, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: iterate command grants: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// ListAllCommandSecretGrantsPage is the tenant inventory variant used by
// operator/read-model surfaces that need every command ACL row. It retains the
// same owner checks as ListCommandSecretGrantsPage and never crosses tenantID.
func (j *Journal) ListAllCommandSecretGrantsPage(ctx context.Context, tenantID string, limit, offset int) ([]CommandGrant, bool, error) {
	tenantID = normalizeCommandGrantTenant(tenantID)
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, false, errors.New("journal: list command grants: page limit exceeds 500")
	}
	if offset < 0 {
		return nil, false, errors.New("journal: list command grants: negative offset")
	}
	const q = `SELECT g.automation_id, g.tenant_id, g.credential_id, g.granted_at, g.granted_by, g.note
		FROM command_automation_secret_grants g
		JOIN command_automations a ON a.id = g.automation_id AND a.tenant_id = g.tenant_id
		WHERE g.tenant_id = $1
		  AND (EXISTS (SELECT 1 FROM credentials c
		               WHERE c.id = g.credential_id AND c.tenant_id = g.tenant_id AND c.deleted_at IS NULL)
		       OR EXISTS (SELECT 1 FROM oauth_connections o
		                  WHERE g.credential_id = 'oauth:' || o.id AND o.tenant_id = g.tenant_id))
		ORDER BY g.automation_id, g.credential_id LIMIT $2 OFFSET $3`
	rows, err := j.db.QueryContext(ctx, j.bind(q), tenantID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("journal: list all command grants: %w", err)
	}
	defer rows.Close()
	out := make([]CommandGrant, 0, limit)
	for rows.Next() {
		var (
			grant                            CommandGrant
			grantedAt, grantedByAny, noteAny any
		)
		if err := rows.Scan(&grant.AutomationID, &grant.TenantID, &grant.CredentialID, &grantedAt, &grantedByAny, &noteAny); err != nil {
			return nil, false, fmt.Errorf("journal: scan command grant: %w", err)
		}
		grant.GrantedAt = j.anyTime(grantedAt)
		grant.GrantedBy = anyToString(grantedByAny)
		grant.Note = anyToString(noteAny)
		out = append(out, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("journal: iterate all command grants: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func normalizeCommandGrantTenant(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return DefaultTenant
	}
	return tenantID
}

// resolveCommandGrantTargets resolves both sides of a grant and maps unknown
// resources to the same target error used by the workflow ACL. HasCommandGrant
// deliberately maps this error to a denial; write operations surface it to the
// caller so phantom grants cannot be persisted.
func (j *Journal) resolveCommandGrantTargets(ctx context.Context, tenantID, automationID, credentialID string) (CommandAutomation, string, error) {
	automationID = strings.TrimSpace(automationID)
	credentialID = strings.TrimSpace(credentialID)
	if automationID == "" || credentialID == "" {
		return CommandAutomation{}, "", errors.New("journal: command grant: automation_id and credential_id required")
	}
	automation, err := j.GetCommandAutomation(ctx, tenantID, automationID)
	if errors.Is(err, ErrNotFound) {
		return CommandAutomation{}, "", fmt.Errorf("%w: command automation %q", ErrGrantTarget, automationID)
	}
	if err != nil {
		return CommandAutomation{}, "", fmt.Errorf("journal: command grant: lookup automation: %w", err)
	}
	credentialTenant, err := j.SecretTenant(ctx, credentialID)
	if errors.Is(err, ErrNotFound) {
		return CommandAutomation{}, "", fmt.Errorf("%w: credential %q", ErrGrantTarget, credentialID)
	}
	if err != nil {
		return CommandAutomation{}, "", fmt.Errorf("journal: command grant: lookup credential tenant: %w", err)
	}
	return automation, credentialTenant, nil
}
