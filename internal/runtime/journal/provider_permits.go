package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	providerPermitWindow   = time.Minute
	providerPermitLeaseTTL = time.Minute
	maxProviderCooldown    = 24 * time.Hour
)

var (
	ErrProviderAccountUnavailable = errors.New("journal: provider account is unavailable")
	ErrProviderPolicyMismatch     = errors.New("journal: provider account budget policy mismatch")
	ErrProviderPermitUnavailable  = errors.New("journal: provider permit is unavailable")
)

// ProviderPermitPolicy is the host-owned budget for one connected account.
// All workers must pass the same policy: the first call persists it and a
// different later value fails closed until an operator migrates the policy.
type ProviderPermitPolicy struct {
	RequestsPerMinute int
	MaxConcurrent     int
}

// ProviderPermit is an opaque host-side lease. A workflow must never choose
// this identity or receive it over the child/host wire.
type ProviderPermit struct {
	ID           string
	TenantID     string
	ConnectionID string
}

// ProviderPermitDeniedError is a durable account budget refusal. RetryAfter
// is a bounded advisory wait; callers must not retry before reacquiring a
// fresh permit. No credential or provider response content enters Error().
type ProviderPermitDeniedError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *ProviderPermitDeniedError) Error() string {
	return "journal: provider account request denied: " + e.Reason
}

// AcquireProviderPermit reserves one actual outbound request attempt. It
// verifies the connection belongs to the tenant, serializes by account row,
// and counts both a rolling minute of issued permits and current in-flight
// leases. Database and policy failures deny the request before network I/O.
func (j *Journal) AcquireProviderPermit(ctx context.Context, tenantID, connectionID string, policy ProviderPermitPolicy) (ProviderPermit, error) {
	var empty ProviderPermit
	if !validProviderPermitIdentity(tenantID) || !validProviderPermitIdentity(connectionID) ||
		policy.RequestsPerMinute < 1 || policy.RequestsPerMinute > 600 ||
		policy.MaxConcurrent < 1 || policy.MaxConcurrent > 32 {
		return empty, errors.New("journal: invalid provider account permit parameters")
	}
	var txOpts *sql.TxOptions
	if j.engine == EnginePostgres {
		txOpts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := j.db.BeginTx(ctx, txOpts)
	if err != nil {
		return empty, fmt.Errorf("journal: begin provider account permit: %w", err)
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT status FROM oauth_connections WHERE id = $1 AND tenant_id = $2`), connectionID, tenantID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return empty, ErrProviderAccountUnavailable
		}
		return empty, fmt.Errorf("journal: verify provider account: %w", err)
	}
	if status != "connected" {
		return empty, ErrProviderAccountUnavailable
	}
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO provider_account_budgets
		(tenant_id, connection_id, requests_per_min, max_concurrent)
		VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, connection_id) DO NOTHING`),
		tenantID, connectionID, policy.RequestsPerMinute, policy.MaxConcurrent); err != nil {
		return empty, fmt.Errorf("journal: create provider account budget: %w", err)
	}
	if j.engine == EngineSQLite {
		// SQLite has no FOR UPDATE. A write inside this transaction serializes
		// all later count/insert work with other SQLite writers.
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_account_budgets SET requests_per_min = requests_per_min
			WHERE tenant_id = $1 AND connection_id = $2`), tenantID, connectionID); err != nil {
			return empty, fmt.Errorf("journal: lock provider account budget: %w", err)
		}
	}
	lockSuffix := ""
	if j.engine == EnginePostgres {
		lockSuffix = " FOR UPDATE"
	}
	var stored ProviderPermitPolicy
	var cooldownRaw any
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT requests_per_min, max_concurrent, cooldown_until
		FROM provider_account_budgets WHERE tenant_id = $1 AND connection_id = $2`+lockSuffix),
		tenantID, connectionID).Scan(&stored.RequestsPerMinute, &stored.MaxConcurrent, &cooldownRaw); err != nil {
		return empty, fmt.Errorf("journal: lock provider account budget: %w", err)
	}
	if stored != policy {
		return empty, ErrProviderPolicyMismatch
	}
	now, err := j.providerPermitNowTx(ctx, tx)
	if err != nil {
		return empty, err
	}
	deny := func(reason string, wait time.Duration) (ProviderPermit, error) {
		// The request was not charged, but old receipts are pruned even when
		// this attempt is denied during a long shared cooldown.
		if err := tx.Commit(); err != nil {
			return empty, fmt.Errorf("journal: commit provider account denial: %w", err)
		}
		return empty, &ProviderPermitDeniedError{Reason: reason, RetryAfter: wait}
	}
	cooldown, err := j.providerPermitTime(cooldownRaw)
	if err != nil {
		return empty, fmt.Errorf("journal: decode provider cooldown: %w", err)
	}
	cutoff := now.Add(-providerPermitWindow)
	if _, err := tx.ExecContext(ctx, j.bind(`DELETE FROM provider_account_permits
		WHERE tenant_id = $1 AND connection_id = $2 AND granted_at < $3
		AND (completed_at IS NOT NULL OR expires_at <= $4)`),
		tenantID, connectionID, j.formatTime(cutoff), j.formatTime(now)); err != nil {
		return empty, fmt.Errorf("journal: prune provider account permits: %w", err)
	}
	if now.Before(cooldown) {
		return deny("cooldown", min(maxProviderCooldown, cooldown.Sub(now)))
	}
	var issued, active int
	var oldestRaw, nextExpiryRaw any
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*), MIN(granted_at) FROM provider_account_permits
		WHERE tenant_id = $1 AND connection_id = $2 AND granted_at >= $3`),
		tenantID, connectionID, j.formatTime(cutoff)).Scan(&issued, &oldestRaw); err != nil {
		return empty, fmt.Errorf("journal: count provider account rate: %w", err)
	}
	if issued >= policy.RequestsPerMinute {
		oldest, err := j.providerPermitTime(oldestRaw)
		if err != nil {
			return empty, fmt.Errorf("journal: decode provider account rate window: %w", err)
		}
		return deny("rate_limit", max(time.Millisecond, oldest.Add(providerPermitWindow).Sub(now)))
	}
	if err := tx.QueryRowContext(ctx, j.bind(`SELECT COUNT(*), MIN(expires_at) FROM provider_account_permits
		WHERE tenant_id = $1 AND connection_id = $2 AND completed_at IS NULL AND expires_at > $3`),
		tenantID, connectionID, j.formatTime(now)).Scan(&active, &nextExpiryRaw); err != nil {
		return empty, fmt.Errorf("journal: count provider account concurrency: %w", err)
	}
	if active >= policy.MaxConcurrent {
		nextExpiry, err := j.providerPermitTime(nextExpiryRaw)
		if err != nil {
			return empty, fmt.Errorf("journal: decode provider account lease: %w", err)
		}
		return deny("concurrency", max(time.Millisecond, nextExpiry.Sub(now)))
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return empty, fmt.Errorf("journal: create provider permit identity: %w", err)
	}
	permit := ProviderPermit{ID: hex.EncodeToString(idBytes[:]), TenantID: tenantID, ConnectionID: connectionID}
	if _, err := tx.ExecContext(ctx, j.bind(`INSERT INTO provider_account_permits
		(id, tenant_id, connection_id, granted_at, expires_at) VALUES ($1, $2, $3, $4, $5)`),
		permit.ID, tenantID, connectionID, j.formatTime(now), j.formatTime(now.Add(providerPermitLeaseTTL))); err != nil {
		return empty, fmt.Errorf("journal: insert provider account permit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("journal: commit provider account permit: %w", err)
	}
	return permit, nil
}

// CompleteProviderPermit releases one in-flight lease after the broker has
// read or failed the HTTP response. The host passes a Retry-After duration
// only for a provider 429. A positive value extends a shared cooldown, capped
// at 24 hours; the rolling-minute request receipt remains until it ages out.
func (j *Journal) CompleteProviderPermit(ctx context.Context, permit ProviderPermit, retryAfter time.Duration) error {
	if !validProviderPermitIdentity(permit.TenantID) || !validProviderPermitIdentity(permit.ConnectionID) || len(permit.ID) != 32 {
		return ErrProviderPermitUnavailable
	}
	if retryAfter < 0 {
		return errors.New("journal: invalid provider cooldown")
	}
	if retryAfter > maxProviderCooldown {
		retryAfter = maxProviderCooldown
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("journal: begin provider permit completion: %w", err)
	}
	defer tx.Rollback()
	if j.engine == EngineSQLite {
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_account_budgets SET requests_per_min = requests_per_min
			WHERE tenant_id = $1 AND connection_id = $2`), permit.TenantID, permit.ConnectionID); err != nil {
			return fmt.Errorf("journal: lock provider account completion: %w", err)
		}
	} else {
		var connectionID string
		if err := tx.QueryRowContext(ctx, `SELECT connection_id FROM provider_account_budgets
			WHERE tenant_id = $1 AND connection_id = $2 FOR UPDATE`, permit.TenantID, permit.ConnectionID).Scan(&connectionID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrProviderPermitUnavailable
			}
			return fmt.Errorf("journal: lock provider account completion: %w", err)
		}
	}
	now, err := j.providerPermitNowTx(ctx, tx)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_account_permits SET completed_at = $1
		WHERE id = $2 AND tenant_id = $3 AND connection_id = $4 AND completed_at IS NULL`),
		j.formatTime(now), permit.ID, permit.TenantID, permit.ConnectionID)
	if err != nil {
		return fmt.Errorf("journal: complete provider permit: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrProviderPermitUnavailable
	}
	if retryAfter > 0 {
		until := j.formatTime(now.Add(retryAfter))
		if _, err := tx.ExecContext(ctx, j.bind(`UPDATE provider_account_budgets
			SET cooldown_until = CASE WHEN cooldown_until IS NULL OR cooldown_until < $1 THEN $2 ELSE cooldown_until END
			WHERE tenant_id = $3 AND connection_id = $4`),
			until, until, permit.TenantID, permit.ConnectionID); err != nil {
			return fmt.Errorf("journal: set provider account cooldown: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("journal: commit provider permit completion: %w", err)
	}
	return nil
}

func validProviderPermitIdentity(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

func (j *Journal) providerPermitNowTx(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	if j.engine == EnginePostgres {
		var now time.Time
		// NOW() is the transaction-start timestamp, which can be stale after
		// waiting on another worker's account-row lock.
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return time.Time{}, fmt.Errorf("journal: read provider account clock: %w", err)
		}
		return now.UTC(), nil
	}
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')`).Scan(&raw); err != nil {
		return time.Time{}, fmt.Errorf("journal: read provider account clock: %w", err)
	}
	return j.parseTime(raw)
}

func (j *Journal) providerPermitTime(raw any) (time.Time, error) {
	switch v := raw.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return v.UTC(), nil
	case string:
		return j.parseTime(v)
	case []byte:
		return j.parseTime(string(v))
	default:
		return time.Time{}, errors.New("unsupported provider account time")
	}
}
