package oauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrRawTokenDenied = errors.New("oauth: raw token access denied")

// isKnownSalesforceOAuthEndpoint recognizes Salesforce-operated OAuth hosts.
// It cannot identify custom domains or a proxy that forwards to Salesforce.
// Host matching is label-boundary-aware and covers the documented login,
// sandbox, My Domain, and Experience Cloud host forms.
func isKnownSalesforceOAuthEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return false
	}
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	for _, domain := range []string{"salesforce.com", "my.site.com", "force.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func rawTokenAllowedForProvider(providerID, authURL, tokenURL string) bool {
	return providerID != "salesforce" &&
		!isKnownSalesforceOAuthEndpoint(authURL) &&
		!isKnownSalesforceOAuthEndpoint(tokenURL)
}

func legacyRawReasonAllows(providerID, authURL, tokenURL, requestedScopes, grantedScopes, reason string) bool {
	if !rawTokenAllowedForProvider(providerID, authURL, tokenURL) {
		return false
	}
	switch reason {
	case "grandfathered":
		return true
	case "email_adapter":
		return legacyEmailRawException(providerID, authURL, tokenURL) &&
			legacyEmailScopesAllowed(providerID, requestedScopes, grantedScopes)
	default:
		return false
	}
}

// RawTokenAllowed checks the current tenant-owned connection and provider
// endpoints before the legacy SecretFetch route may return an OAuth token to
// a workflow child. Existing alias rows must be checked at use time too:
// registration validation alone cannot protect rows created before it.
func (s *Store) RawTokenAllowed(ctx context.Context, connectionID, tenantID string) (bool, error) {
	if connectionID == "" || tenantID == "" {
		return false, ErrNotFound
	}
	const q = `SELECT p.provider_id, p.auth_url, p.token_url, p.scopes, p.enabled, c.scopes,
		c.status, c.token_access_mode, c.legacy_raw_reason
		FROM oauth_connections c JOIN oauth_providers p ON p.provider_id = c.provider_id
		WHERE c.id = $1 AND c.tenant_id = $2`
	var providerID, authURL, tokenURL, requestedScopes, grantedScopes, status, accessMode, legacyReason string
	var enabled any
	if err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).
		Scan(&providerID, &authURL, &tokenURL, &requestedScopes, &enabled, &grantedScopes,
			&status, &accessMode, &legacyReason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, wrap("check OAuth raw token policy", err)
	}
	return status == "connected" && accessMode == "legacy_raw" && parseBool(enabled) &&
		legacyRawReasonAllows(providerID, authURL, tokenURL, requestedScopes, grantedScopes, legacyReason), nil
}

// RawToken is the only accessor for a legacy workflow's raw OAuth token. It
// refreshes when necessary, then reads the current encrypted token and its
// provider policy in one joined SQL statement. This final check prevents a
// provider endpoint edit or reconnect between preflight and refresh from
// releasing a token whose current provider is Salesforce.
func (s *Store) RawToken(ctx context.Context, connectionID, tenantID string) (string, error) {
	allowed, err := s.RawTokenAllowed(ctx, connectionID, tenantID)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrRawTokenDenied
	}
	if _, err := s.Token(ctx, connectionID, tenantID); err != nil {
		return "", err
	}
	const q = `SELECT c.provider_id, c.name, c.token_encrypted, c.status, c.token_access_mode,
		c.legacy_raw_reason, p.auth_url, p.token_url, p.scopes, p.enabled, c.scopes
		FROM oauth_connections c JOIN oauth_providers p ON p.provider_id = c.provider_id
		WHERE c.id = $1 AND c.tenant_id = $2`
	var providerID, name, status, accessMode, legacyReason, authURL, tokenURL, requestedScopes, grantedScopes string
	var enc []byte
	var enabled any
	if err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).
		Scan(&providerID, &name, &enc, &status, &accessMode, &legacyReason,
			&authURL, &tokenURL, &requestedScopes, &enabled, &grantedScopes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", wrap("load raw OAuth token", err)
	}
	if status != "connected" || accessMode != "legacy_raw" || !parseBool(enabled) ||
		!legacyRawReasonAllows(providerID, authURL, tokenURL, requestedScopes, grantedScopes, legacyReason) {
		return "", ErrRawTokenDenied
	}
	tb, err := s.loadTokenBlob(enc, connectionTokenIdentity(tenantID, providerID, name))
	if err != nil {
		return "", fmt.Errorf("oauth: decrypt raw token: %w", err)
	}
	if legacyReason == "email_adapter" && !legacyEmailScopesAllowed(providerID, requestedScopes, tb.Scope) {
		return "", ErrRawTokenDenied
	}
	if tb.AccessToken == "" || (!tb.Expiry.IsZero() && !s.now().UTC().Before(tb.Expiry.Add(-60*time.Second))) {
		return "", errors.New("oauth: connection changed during raw token resolution; retry")
	}
	return tb.AccessToken, nil
}
