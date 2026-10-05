package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ErrSalesforceAPIOriginUnavailable means the connection has no validated
// Salesforce instance origin. Older connections need to reconnect or refresh
// with a response that supplies instance_url before this metadata is present.
var ErrSalesforceAPIOriginUnavailable = errors.New("oauth: Salesforce API origin unavailable")
var ErrSalesforceOrgIDUnavailable = errors.New("oauth: Salesforce organization identity unavailable; reconnect the account")

const maxSalesforceAPIOriginBytes = 2048

// salesforceOrgFromIdentityURL accepts the Salesforce OAuth token response's
// identity URL, not one supplied by a workflow. The first path ID is the org
// ID; the second is the user ID. Restricting both and the host prevents a
// malformed response from creating an arbitrary shared-budget namespace.
func salesforceOrgFromIdentityURL(raw string) (string, error) {
	invalid := func() (string, error) { return "", errors.New("oauth: invalid Salesforce identity URL") }
	if raw == "" || len(raw) > maxSalesforceAPIOriginBytes || raw != strings.TrimSpace(raw) {
		return invalid()
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.Host != u.Hostname() || u.RawPath != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.Contains(raw, "#") ||
		strings.Contains(u.EscapedPath(), "%") {
		return invalid()
	}
	if _, err := validateSalesforceAPIOrigin("https://" + u.Host); err != nil {
		return invalid()
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "id" ||
		!validSalesforceOrgID(parts[2]) || !validSalesforceID(parts[3], "005") {
		return invalid()
	}
	return parts[2][:15], nil
}

func validSalesforceID(id, prefix string) bool {
	if (len(id) != 15 && len(id) != 18) || !strings.HasPrefix(id, prefix) {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func validSalesforceOrgID(id string) bool { return validSalesforceID(id, "00D") }

func salesforceAccountKey(orgID string) string {
	sum := sha256.Sum256([]byte("reactor-provider-account-v1\x00salesforce\x00" + orgID[:15]))
	return hex.EncodeToString(sum[:])
}

// validateSalesforceAPIOrigin accepts only a bare Salesforce HTTPS org origin.
// The OAuth response is provider data, not authority to send a credential to
// an arbitrary host. Unusual custom domains need a separate reviewed policy.
func validateSalesforceAPIOrigin(raw string) (string, error) {
	invalid := func() (string, error) { return "", errors.New("oauth: invalid Salesforce API origin") }
	if raw == "" || len(raw) > maxSalesforceAPIOriginBytes || raw != strings.TrimSpace(raw) {
		return invalid()
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.Host != u.Hostname() || (u.Path != "" && u.Path != "/") ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || strings.Contains(raw, "#") {
		return invalid()
	}
	host := strings.ToLower(u.Hostname())
	if len(host) > 253 || !strings.HasSuffix(host, ".salesforce.com") {
		return invalid()
	}
	orgHost := strings.TrimSuffix(host, ".salesforce.com")
	if orgHost == "" {
		return invalid()
	}
	for _, label := range strings.Split(orgHost, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid()
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return invalid()
			}
		}
	}
	return "https://" + host, nil
}

// ValidateSalesforceAPIOrigin is shared with the supervisor's host HTTP
// boundary. Rechecking there prevents a custom resolver from replacing the
// OAuth store with an unsafe origin while preserving a narrow interface.
func ValidateSalesforceAPIOrigin(raw string) (string, error) {
	return validateSalesforceAPIOrigin(raw)
}

// SalesforceAPIOrigin returns only the validated API origin for a Salesforce
// connection owned by tenantID. It never returns or refreshes token values.
// This metadata is not itself permission to send credentials: a future HTTP
// broker must resolve the current token and enforce the approved origin in
// one operation, with the workflow grant and version checks.
func (s *Store) SalesforceAPIOrigin(ctx context.Context, connectionID, tenantID string) (string, error) {
	if connectionID == "" || tenantID == "" {
		return "", ErrNotFound
	}
	const q = `SELECT name, token_encrypted FROM oauth_connections
		WHERE id = $1 AND tenant_id = $2 AND provider_id = 'salesforce'`
	var name string
	var enc []byte
	if err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).Scan(&name, &enc); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", wrap("load Salesforce connection metadata", err)
	}
	tb, err := s.loadTokenBlob(enc, connectionTokenIdentity(tenantID, "salesforce", name))
	if err != nil {
		return "", fmt.Errorf("oauth: decrypt Salesforce connection metadata: %w", err)
	}
	if tb.SalesforceAPIOrigin == "" {
		return "", ErrSalesforceAPIOriginUnavailable
	}
	origin, err := validateSalesforceAPIOrigin(tb.SalesforceAPIOrigin)
	if err != nil {
		return "", ErrSalesforceAPIOriginUnavailable
	}
	return origin, nil
}

// ConnectionProvider returns only the provider id for a tenant-owned OAuth
// connection. The supervisor uses it to deny raw Salesforce token fetches so
// the host-brokered origin policy cannot be bypassed by a workflow child.
func (s *Store) ConnectionProvider(ctx context.Context, connectionID, tenantID string) (string, error) {
	if connectionID == "" || tenantID == "" {
		return "", ErrNotFound
	}
	const q = `SELECT provider_id FROM oauth_connections WHERE id = $1 AND tenant_id = $2`
	var providerID string
	if err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).Scan(&providerID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", wrap("load connection provider", err)
	}
	return providerID, nil
}

// SalesforceSession resolves a fresh token and returns it with the validated
// origin from one current encrypted connection row. This is host-only: neither
// value is exposed through MCP, and the token is never sent to the workflow
// child on the brokered path. Reading both fields from one row avoids pairing
// a token from before a concurrent reconnect with a newer origin.
func (s *Store) SalesforceSession(ctx context.Context, connectionID, tenantID string) (token, origin string, err error) {
	token, origin, _, err = s.salesforceSession(ctx, connectionID, tenantID)
	return token, origin, err
}

// SalesforceBrokerSession atomically pairs the current token, validated API
// origin, and host-derived shared budget key. Legacy connections without a
// provider identity fail closed until reconnect or a refresh supplies it.
func (s *Store) SalesforceBrokerSession(ctx context.Context, connectionID, tenantID string) (token, origin, accountKey string, err error) {
	token, origin, orgID, err := s.salesforceSession(ctx, connectionID, tenantID)
	if err != nil {
		return "", "", "", err
	}
	if !validSalesforceOrgID(orgID) {
		return "", "", "", ErrSalesforceOrgIDUnavailable
	}
	return token, origin, salesforceAccountKey(orgID), nil
}

// SalesforceBrokerSessionCurrent checks the exact host-side session tuple
// immediately before egress and before releasing a provider response. It
// reads one current connection row without refreshing or sending a token to
// the workflow. A reconnect, disable, disconnect, or expiry denies the old
// tuple even if the workflow grant and worker lease are still valid.
func (s *Store) SalesforceBrokerSessionCurrent(ctx context.Context, connectionID, tenantID, token, origin, accountKey string) (bool, error) {
	if connectionID == "" || tenantID == "" || token == "" || origin == "" || accountKey == "" {
		return false, nil
	}
	const q = `SELECT c.name, c.token_encrypted, c.status, p.enabled FROM oauth_connections c
		JOIN oauth_providers p ON p.provider_id=c.provider_id
		WHERE c.id=$1 AND c.tenant_id=$2 AND c.provider_id='salesforce'`
	var name, status string
	var enc []byte
	var enabled any
	err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).Scan(&name, &enc, &status, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrap("recheck Salesforce session", err)
	}
	if status != "connected" || !parseBool(enabled) {
		return false, nil
	}
	tb, err := s.loadTokenBlob(enc, connectionTokenIdentity(tenantID, "salesforce", name))
	if err != nil {
		return false, errors.New("oauth: Salesforce session verification unavailable")
	}
	if tb.AccessToken == "" || (!tb.Expiry.IsZero() && !s.now().UTC().Before(tb.Expiry.Add(-60*time.Second))) ||
		!validSalesforceOrgID(tb.SalesforceOrgID) {
		return false, nil
	}
	currentOrigin, err := validateSalesforceAPIOrigin(tb.SalesforceAPIOrigin)
	if err != nil {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(tb.AccessToken), []byte(token)) == 1 &&
		currentOrigin == origin && salesforceAccountKey(tb.SalesforceOrgID) == accountKey, nil
}

func (s *Store) salesforceSession(ctx context.Context, connectionID, tenantID string) (token, origin, orgID string, err error) {
	if connectionID == "" || tenantID == "" {
		return "", "", "", ErrNotFound
	}
	// Disabled providers are an operator kill switch, not merely hidden from
	// the connect page. Refuse even a token refresh until re-enabled.
	var preStatus string
	var preEnabled any
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT c.status, p.enabled FROM oauth_connections c
		JOIN oauth_providers p ON p.provider_id=c.provider_id
		WHERE c.id=$1 AND c.tenant_id=$2 AND c.provider_id='salesforce'`),
		connectionID, tenantID).Scan(&preStatus, &preEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrNotFound
	}
	if err != nil {
		return "", "", "", wrap("preflight Salesforce session", err)
	}
	if preStatus != "connected" || !parseBool(preEnabled) {
		return "", "", "", ErrNotFound
	}
	if _, err := s.Token(ctx, connectionID, tenantID); err != nil {
		return "", "", "", err
	}
	const q = `SELECT c.name, c.token_encrypted, c.status, p.enabled FROM oauth_connections c
		JOIN oauth_providers p ON p.provider_id=c.provider_id
		WHERE c.id = $1 AND c.tenant_id = $2 AND c.provider_id = 'salesforce'`
	var name, status string
	var enc []byte
	var enabled any
	if err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).Scan(&name, &enc, &status, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", ErrNotFound
		}
		return "", "", "", wrap("load Salesforce session", err)
	}
	tb, err := s.loadTokenBlob(enc, connectionTokenIdentity(tenantID, "salesforce", name))
	if err != nil {
		return "", "", "", fmt.Errorf("oauth: decrypt Salesforce session: %w", err)
	}
	if status != "connected" || !parseBool(enabled) || tb.AccessToken == "" ||
		(!tb.Expiry.IsZero() && !s.now().UTC().Before(tb.Expiry.Add(-60*time.Second))) {
		return "", "", "", errors.New("oauth: Salesforce session is not current")
	}
	origin, err = validateSalesforceAPIOrigin(tb.SalesforceAPIOrigin)
	if err != nil {
		return "", "", "", ErrSalesforceAPIOriginUnavailable
	}
	return tb.AccessToken, origin, tb.SalesforceOrgID, nil
}
