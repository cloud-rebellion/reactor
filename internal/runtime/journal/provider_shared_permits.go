package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// SharedProviderPermit is a host-side lease on a provider account. AccountKey
// is a hash of a provider-attested account identity, never workflow input.
type SharedProviderPermit struct {
	ID         string
	TenantID   string
	ProviderID string
	AccountKey string
}

func validProviderAccountKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, c := range key {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// AcquireSharedProviderPermit charges a request attempt to a tenant's
// provider account, even when separate OAuth connections use the same account.
// The caller must obtain accountKey from a validated host-side OAuth session.
// Connection ownership, provider, and connected status are rechecked in the
// admission transaction; any database or policy failure denies network I/O.
func (j *Journal) AcquireSharedProviderPermit(ctx context.Context, tenantID, connectionID, providerID, accountKey string, policy ProviderPermitPolicy) (SharedProviderPermit, error) {
	var empty SharedProviderPermit
	if !validProviderPermitIdentity(tenantID) || !validProviderPermitIdentity(connectionID) ||
		!validProviderPermitIdentity(providerID) || !validProviderAccountKey(accountKey) ||
		policy.RequestsPerMinute < 1 || policy.RequestsPerMinute > 600 ||
		policy.MaxConcurrent < 1 || policy.MaxConcurrent > 32 {
		return empty, errors.New("journal: invalid shared provider permit parameters")
	}
	var txOpts *sql.TxOptions
	if j.engine == EnginePostgres {
		txOpts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := j.db.BeginTx(ctx, txOpts)
	if err != nil {
		return empty, fmt.Errorf("journal: begin shared provider permit: %w", err)
	}
	defer tx.Rollback()
	var status, storedProvider string
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status, provider_id FROM oauth_connections
		WHERE id = $1 AND tenant_id = $2`), connectionID, tenantID).Scan(&status, &storedProvider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return empty, ErrProviderAccountUnavailable
		}
		return empty, fmt.Errorf("journal: verify shared provider connection: %w", err)
	}
	if status != "connected" || storedProvider != providerID {
		return empty, ErrProviderAccountUnavailable
	}
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO provider_shared_account_budgets
		(tenant_id, provider_id, account_key, requests_per_min, max_concurrent)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, provider_id, account_key) DO NOTHING`),
		tenantID, providerID, accountKey, policy.RequestsPerMinute, policy.MaxConcurrent); err != nil {
		return empty, fmt.Errorf("journal: create shared provider budget: %w", err)
	}
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_shared_account_budgets
			SET requests_per_min = requests_per_min
			WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3`),
			tenantID, providerID, accountKey); err != nil {
			return empty, fmt.Errorf("journal: lock shared provider budget: %w", err)
		}
	}
	lockSuffix := ""
	if j.engine == EnginePostgres {
		lockSuffix = " FOR UPDATE"
	}
	var stored ProviderPermitPolicy
	var cooldownRaw any
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT requests_per_min, max_concurrent, cooldown_until
		FROM provider_shared_account_budgets
		WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3`+lockSuffix),
		tenantID, providerID, accountKey).Scan(&stored.RequestsPerMinute, &stored.MaxConcurrent, &cooldownRaw); err != nil {
		return empty, fmt.Errorf("journal: lock shared provider budget: %w", err)
	}
	if stored != policy {
		return empty, ErrProviderPolicyMismatch
	}
	now, err := j.providerPermitNowTx(ctx, tx)
	if err != nil {
		return empty, err
	}
	deny := func(reason string, wait time.Duration) (SharedProviderPermit, error) {
		if err := tx.Commit(); err != nil {
			return empty, fmt.Errorf("journal: commit shared provider denial: %w", err)
		}
		return empty, &ProviderPermitDeniedError{Reason: reason, RetryAfter: wait}
	}
	cooldown, err := j.providerPermitTime(cooldownRaw)
	if err != nil {
		return empty, fmt.Errorf("journal: decode shared provider cooldown: %w", err)
	}
	cutoff := now.Add(-providerPermitWindow)
	if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM provider_shared_account_permits
		WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3
		AND granted_at < $4 AND (completed_at IS NOT NULL OR expires_at <= $5)`),
		tenantID, providerID, accountKey, j.formatTime(cutoff), j.formatTime(now)); err != nil {
		return empty, fmt.Errorf("journal: prune shared provider permits: %w", err)
	}
	if now.Before(cooldown) {
		return deny("cooldown", min(maxProviderCooldown, cooldown.Sub(now)))
	}
	var issued, active int
	var oldestRaw, nextExpiryRaw any
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*), MIN(granted_at) FROM provider_shared_account_permits
		WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3 AND granted_at >= $4`),
		tenantID, providerID, accountKey, j.formatTime(cutoff)).Scan(&issued, &oldestRaw); err != nil {
		return empty, fmt.Errorf("journal: count shared provider rate: %w", err)
	}
	if issued >= policy.RequestsPerMinute {
		oldest, err := j.providerPermitTime(oldestRaw)
		if err != nil {
			return empty, fmt.Errorf("journal: decode shared provider rate window: %w", err)
		}
		return deny("rate_limit", max(time.Millisecond, oldest.Add(providerPermitWindow).Sub(now)))
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*), MIN(expires_at) FROM provider_shared_account_permits
		WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3
		AND completed_at IS NULL AND expires_at > $4`),
		tenantID, providerID, accountKey, j.formatTime(now)).Scan(&active, &nextExpiryRaw); err != nil {
		return empty, fmt.Errorf("journal: count shared provider concurrency: %w", err)
	}
	if active >= policy.MaxConcurrent {
		nextExpiry, err := j.providerPermitTime(nextExpiryRaw)
		if err != nil {
			return empty, fmt.Errorf("journal: decode shared provider lease: %w", err)
		}
		return deny("concurrency", max(time.Millisecond, nextExpiry.Sub(now)))
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return empty, fmt.Errorf("journal: create shared provider permit identity: %w", err)
	}
	permit := SharedProviderPermit{ID: hex.EncodeToString(idBytes[:]), TenantID: tenantID,
		ProviderID: providerID, AccountKey: accountKey}
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO provider_shared_account_permits
		(id, tenant_id, provider_id, account_key, source_connection_id, granted_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`),
		permit.ID, tenantID, providerID, accountKey, connectionID, j.formatTime(now),
		j.formatTime(now.Add(providerPermitLeaseTTL))); err != nil {
		return empty, fmt.Errorf("journal: insert shared provider permit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("journal: commit shared provider permit: %w", err)
	}
	return permit, nil
}

// CompleteSharedProviderPermit releases the active lease, retaining the
// rolling-minute attempt receipt and applying a provider 429 cooldown.
func (j *Journal) CompleteSharedProviderPermit(ctx context.Context, permit SharedProviderPermit, retryAfter time.Duration) error {
	if !validProviderPermitIdentity(permit.TenantID) || !validProviderPermitIdentity(permit.ProviderID) ||
		!validProviderAccountKey(permit.AccountKey) || len(permit.ID) != 32 {
		return ErrProviderPermitUnavailable
	}
	if retryAfter < 0 {
		return errors.New("journal: invalid shared provider cooldown")
	}
	if retryAfter > maxProviderCooldown {
		retryAfter = maxProviderCooldown
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin shared provider permit completion: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_shared_account_budgets
			SET requests_per_min = requests_per_min
			WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3`),
			permit.TenantID, permit.ProviderID, permit.AccountKey); err != nil {
			return fmt.Errorf("journal: lock shared provider completion: %w", err)
		}
	} else {
		var accountKey string
		if err := tx.QueryRowContext(ctx, `SELECT account_key FROM provider_shared_account_budgets
			WHERE tenant_id = $1 AND provider_id = $2 AND account_key = $3 FOR UPDATE`,
			permit.TenantID, permit.ProviderID, permit.AccountKey).Scan(&accountKey); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrProviderPermitUnavailable
			}
			return fmt.Errorf("journal: lock shared provider completion: %w", err)
		}
	}
	now, err := j.providerPermitNowTx(ctx, tx)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_shared_account_permits SET completed_at = $1
		WHERE id = $2 AND tenant_id = $3 AND provider_id = $4 AND account_key = $5
		AND completed_at IS NULL`), j.formatTime(now), permit.ID, permit.TenantID,
		permit.ProviderID, permit.AccountKey)
	if err != nil {
		return fmt.Errorf("journal: complete shared provider permit: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrProviderPermitUnavailable
	}
	if retryAfter > 0 {
		until := j.formatTime(now.Add(retryAfter))
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_shared_account_budgets
			SET cooldown_until = CASE WHEN cooldown_until IS NULL OR cooldown_until < $1 THEN $2 ELSE cooldown_until END
			WHERE tenant_id = $3 AND provider_id = $4 AND account_key = $5`),
			until, until, permit.TenantID, permit.ProviderID, permit.AccountKey); err != nil {
			return fmt.Errorf("journal: persist shared provider cooldown: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit shared provider permit completion: %w", err)
	}
	return nil
}
