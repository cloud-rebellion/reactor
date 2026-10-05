package oauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/safehttp"
)

// BrokerPolicy is the latest operator-reviewed, tenant-scoped generic GET
// contract. An absent policy never permits raw token access for a broker-only
// connection. The version is an optimistic edit fence and an audit reference.
type BrokerPolicy struct {
	ConnectionID string
	TenantID     string
	ProviderID   string
	Version      int64
	APIOrigin    string
	PathPrefix   string
	Method       string
	ReviewedBy   string
	ReviewedAt   time.Time
}

// BrokerSession pairs a current encrypted token row with its reviewed policy.
// It is host-only; token bytes and the ciphertext fingerprint stay private.
type BrokerSession struct {
	BrokerPolicy
	token           string
	tokenCipherHash [sha256.Size]byte
}

// BearerToken is called only by the host transport immediately before egress.
// The unexported field and redacted formatters keep routine JSON/log output
// from accidentally serializing a live access token.
func (s BrokerSession) BearerToken() string { return s.token }

func (s BrokerSession) String() string {
	return fmt.Sprintf("oauth.BrokerSession{connection:%q policy_version:%d token:[REDACTED]}", s.ConnectionID, s.Version)
}

func (s BrokerSession) GoString() string { return s.String() }

var (
	ErrBrokerPolicyUnavailable = errors.New("oauth: reviewed API broker policy unavailable")
	ErrBrokerPolicyConflict    = errors.New("oauth: broker policy changed; reload before approval")
)

// ValidateBrokerAPIOrigin admits an exact public HTTPS origin, with no URL
// credentials, path, query, or fragment. The egress transport separately
// checks the resolved IP at dial time to resist DNS rebinding.
func ValidateBrokerAPIOrigin(raw string) (string, error) {
	if raw == "" || len(raw) > 512 || strings.TrimSpace(raw) != raw {
		return "", ErrBrokerPolicyUnavailable
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", ErrBrokerPolicyUnavailable
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "%\\@") {
		return "", ErrBrokerPolicyUnavailable
	}
	if ip := net.ParseIP(host); ip != nil {
		if safehttp.BlockedIP(ip, false) {
			return "", ErrBrokerPolicyUnavailable
		}
	} else {
		if len(host) > 253 || !strings.Contains(host, ".") {
			return "", ErrBrokerPolicyUnavailable
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrBrokerPolicyUnavailable
			}
			for _, c := range label {
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
					return "", ErrBrokerPolicyUnavailable
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", ErrBrokerPolicyUnavailable
		}
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" && port != "443" {
		authority += ":" + port
	}
	return "https://" + authority, nil
}

// ValidateBrokerPath validates a child-supplied path/query and checks the
// reviewed prefix at a path-segment boundary. Encoded path bytes are rejected
// to avoid traversal and proxy double-decoding ambiguity; query escaping is
// still permitted for ordinary API parameters.
func ValidateBrokerPath(raw, prefix string) (string, error) {
	if len(raw) == 0 || len(raw) > 8192 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") ||
		strings.ContainsAny(raw, "#\\") {
		return "", ErrBrokerPolicyUnavailable
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return "", ErrBrokerPolicyUnavailable
		}
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u == nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" ||
		u.Fragment != "" || strings.Contains(u.EscapedPath(), "%") || strings.HasPrefix(u.Path, "//") {
		return "", ErrBrokerPolicyUnavailable
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "", ErrBrokerPolicyUnavailable
		}
	}
	if prefix != "/" && u.Path != prefix && !strings.HasPrefix(u.Path, strings.TrimSuffix(prefix, "/")+"/") {
		return "", ErrBrokerPolicyUnavailable
	}
	return u.RequestURI(), nil
}

func validateBrokerPrefix(prefix string) error {
	if prefix == "" || len(prefix) > 2048 || strings.ContainsAny(prefix, "?#") {
		return ErrBrokerPolicyUnavailable
	}
	path, err := ValidateBrokerPath(prefix, "/")
	if err != nil || path != prefix {
		return ErrBrokerPolicyUnavailable
	}
	return nil
}

// ApproveBrokerPolicy commits the exact origin/prefix/method an admin has
// reviewed. expectedVersion=0 means first approval; a stale form cannot
// overwrite a newer review. The switch to broker_only is irreversible.
func (s *Store) ApproveBrokerPolicy(ctx context.Context, tenantID, connectionID, reviewer string, expectedVersion int64, origin, prefix, method string) (BrokerPolicy, error) {
	if tenantID == "" || connectionID == "" || len(tenantID) > 512 || len(connectionID) > 512 ||
		reviewer == "" || len(reviewer) > 256 || expectedVersion < 0 || method != "GET" {
		return BrokerPolicy{}, ErrBrokerPolicyUnavailable
	}
	var err error
	origin, err = ValidateBrokerAPIOrigin(origin)
	if err != nil || validateBrokerPrefix(prefix) != nil {
		return BrokerPolicy{}, ErrBrokerPolicyUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BrokerPolicy{}, wrap("begin broker policy approval", err)
	}
	defer tx.Rollback()
	if s.engine == EngineSQLite {
		res, err := tx.ExecContext(ctx, s.bind(`UPDATE oauth_connections SET token_access_mode=token_access_mode WHERE id=$1 AND tenant_id=$2`), connectionID, tenantID)
		if err != nil {
			return BrokerPolicy{}, wrap("lock broker connection", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return BrokerPolicy{}, ErrNotFound
		}
	}
	lock := ""
	if s.engine == EnginePostgres {
		lock = " FOR UPDATE OF c"
	}
	var providerID, status, authURL, tokenURL string
	var enabled any
	err = tx.QueryRowContext(ctx, s.bind(`SELECT c.provider_id, c.status, p.auth_url, p.token_url, p.enabled
		FROM oauth_connections c JOIN oauth_providers p ON p.provider_id=c.provider_id
		WHERE c.id=$1 AND c.tenant_id=$2`+lock), connectionID, tenantID).
		Scan(&providerID, &status, &authURL, &tokenURL, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return BrokerPolicy{}, ErrNotFound
	}
	if err != nil {
		return BrokerPolicy{}, wrap("load broker connection", err)
	}
	if status != "connected" || !parseBool(enabled) || !rawTokenAllowedForProvider(providerID, authURL, tokenURL) {
		return BrokerPolicy{}, ErrBrokerPolicyUnavailable
	}
	var version int64
	err = tx.QueryRowContext(ctx, s.bind(`SELECT version FROM oauth_api_policies WHERE connection_id=$1 AND tenant_id=$2`), connectionID, tenantID).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return BrokerPolicy{}, wrap("read broker policy version", err)
	}
	if version != expectedVersion {
		return BrokerPolicy{}, ErrBrokerPolicyConflict
	}
	if version == 0 {
		// A policy row may have been removed directly in the database. The
		// broker-only mode still denies raw access; a fresh review must not
		// reuse a historical revision number or overwrite its receipt.
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT COALESCE(MAX(version),0) FROM oauth_api_policy_reviews
			WHERE connection_id=$1 AND tenant_id=$2`), connectionID, tenantID).Scan(&version); err != nil {
			return BrokerPolicy{}, wrap("read broker review history", err)
		}
	}
	version++
	now := s.nowVal()
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO oauth_api_policies
		(connection_id, tenant_id, version, api_origin, path_prefix, method, reviewed_by, reviewed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (connection_id) DO UPDATE SET version=excluded.version,
		api_origin=excluded.api_origin, path_prefix=excluded.path_prefix, method=excluded.method,
		reviewed_by=excluded.reviewed_by, reviewed_at=excluded.reviewed_at`),
		connectionID, tenantID, version, origin, prefix, method, reviewer, now)
	if err != nil {
		return BrokerPolicy{}, wrap("save broker policy", err)
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO oauth_api_policy_reviews
		(connection_id, tenant_id, version, api_origin, path_prefix, method, reviewed_by, reviewed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`),
		connectionID, tenantID, version, origin, prefix, method, reviewer, now)
	if err != nil {
		return BrokerPolicy{}, wrap("append broker policy review", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE oauth_connections SET token_access_mode='broker_only', legacy_raw_reason='' WHERE id=$1 AND tenant_id=$2`), connectionID, tenantID); err != nil {
		return BrokerPolicy{}, wrap("switch broker connection mode", err)
	}
	if err := tx.Commit(); err != nil {
		return BrokerPolicy{}, wrap("commit broker policy approval", err)
	}
	return BrokerPolicy{ConnectionID: connectionID, TenantID: tenantID, ProviderID: providerID,
		Version: version, APIOrigin: origin, PathPrefix: prefix, Method: method,
		ReviewedBy: reviewer, ReviewedAt: s.now().UTC()}, nil
}

// GetBrokerPolicy returns the current review without decrypting tokens.
func (s *Store) GetBrokerPolicy(ctx context.Context, tenantID, connectionID string) (BrokerPolicy, error) {
	const q = `SELECT c.provider_id, p.version, p.api_origin, p.path_prefix, p.method, p.reviewed_by, p.reviewed_at
		FROM oauth_api_policies p JOIN oauth_connections c ON c.id=p.connection_id AND c.tenant_id=p.tenant_id
		WHERE p.connection_id=$1 AND p.tenant_id=$2`
	var p BrokerPolicy
	var reviewedAt any
	err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).Scan(&p.ProviderID, &p.Version,
		&p.APIOrigin, &p.PathPrefix, &p.Method, &p.ReviewedBy, &reviewedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BrokerPolicy{}, ErrNotFound
	}
	if err != nil {
		return BrokerPolicy{}, wrap("get broker policy", err)
	}
	p.ConnectionID, p.TenantID, p.ReviewedAt = connectionID, tenantID, s.parseTime(reviewedAt)
	return p, nil
}

// GenericBrokerSession preflights the review before refresh, then reads the
// current token and reviewed policy in one row. The policy is rechecked after admission and
// immediately before outbound HTTP by BrokerPolicyCurrent.
func (s *Store) GenericBrokerSession(ctx context.Context, tenantID, connectionID string) (BrokerSession, error) {
	if tenantID == "" || connectionID == "" {
		return BrokerSession{}, ErrNotFound
	}
	// Do not refresh through the provider for an unreviewed, revoked, or
	// legacy-raw connection. A concurrent edit can still happen after this
	// read, so the final joined row below remains the authorization gate.
	const preflight = `SELECT c.status, c.token_access_mode, p.provider_id, p.auth_url, p.token_url,
		p.enabled, b.version, b.api_origin, b.path_prefix, b.method
		FROM oauth_connections c JOIN oauth_providers p ON p.provider_id=c.provider_id
		JOIN oauth_api_policies b ON b.connection_id=c.id AND b.tenant_id=c.tenant_id
		WHERE c.id=$1 AND c.tenant_id=$2`
	var preStatus, preMode, preProviderID, preAuthURL, preTokenURL, origin, prefix, method string
	var preEnabled any
	var version int64
	err := s.db.QueryRowContext(ctx, s.bind(preflight), connectionID, tenantID).
		Scan(&preStatus, &preMode, &preProviderID, &preAuthURL, &preTokenURL, &preEnabled, &version, &origin, &prefix, &method)
	if errors.Is(err, sql.ErrNoRows) {
		return BrokerSession{}, ErrBrokerPolicyUnavailable
	}
	if err != nil {
		return BrokerSession{}, wrap("preflight broker session", err)
	}
	if preStatus != "connected" || preMode != "broker_only" || !parseBool(preEnabled) ||
		!rawTokenAllowedForProvider(preProviderID, preAuthURL, preTokenURL) || version < 1 || method != "GET" ||
		validateBrokerPrefix(prefix) != nil {
		return BrokerSession{}, ErrBrokerPolicyUnavailable
	}
	if valid, err := ValidateBrokerAPIOrigin(origin); err != nil || valid != origin {
		return BrokerSession{}, ErrBrokerPolicyUnavailable
	}
	if _, err := s.Token(ctx, connectionID, tenantID); err != nil {
		return BrokerSession{}, err
	}
	const q = `SELECT c.provider_id, c.name, c.token_encrypted, c.status, c.token_access_mode,
		p.enabled, p.auth_url, p.token_url,
		b.version, b.api_origin, b.path_prefix, b.method, b.reviewed_by, b.reviewed_at
		FROM oauth_connections c JOIN oauth_providers p ON p.provider_id=c.provider_id
		JOIN oauth_api_policies b ON b.connection_id=c.id AND b.tenant_id=c.tenant_id
		WHERE c.id=$1 AND c.tenant_id=$2`
	var session BrokerSession
	var name, status, mode, authURL, tokenURL string
	var enc []byte
	var enabled, reviewedAt any
	err = s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID).Scan(
		&session.ProviderID, &name, &enc, &status, &mode, &enabled, &authURL, &tokenURL,
		&session.Version, &session.APIOrigin, &session.PathPrefix, &session.Method, &session.ReviewedBy, &reviewedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BrokerSession{}, ErrBrokerPolicyUnavailable
	}
	if err != nil {
		return BrokerSession{}, wrap("load broker session", err)
	}
	if status != "connected" || mode != "broker_only" || !parseBool(enabled) ||
		!rawTokenAllowedForProvider(session.ProviderID, authURL, tokenURL) || session.Version < 1 ||
		session.Method != "GET" || session.ReviewedBy == "" || validateBrokerPrefix(session.PathPrefix) != nil {
		return BrokerSession{}, ErrBrokerPolicyUnavailable
	}
	if origin, err := ValidateBrokerAPIOrigin(session.APIOrigin); err != nil || origin != session.APIOrigin {
		return BrokerSession{}, ErrBrokerPolicyUnavailable
	}
	tb, err := s.loadTokenBlob(enc, connectionTokenIdentity(tenantID, session.ProviderID, name))
	if err != nil {
		return BrokerSession{}, fmt.Errorf("oauth: decrypt broker token: %w", err)
	}
	if tb.AccessToken == "" || (!tb.Expiry.IsZero() && !s.now().UTC().Before(tb.Expiry.Add(-60*time.Second))) {
		return BrokerSession{}, ErrBrokerPolicyUnavailable
	}
	session.ConnectionID, session.TenantID, session.ReviewedAt = connectionID, tenantID, s.parseTime(reviewedAt)
	session.token, session.tokenCipherHash = tb.AccessToken, sha256.Sum256(enc)
	return session, nil
}

// BrokerPolicyCurrent rejects an edited/deleted policy, revoked connection,
// provider change, or reconnect/refresh since GenericBrokerSession. A change
// committed after this check still races an in-flight external GET.
func (s *Store) BrokerPolicyCurrent(ctx context.Context, session BrokerSession) (bool, error) {
	if session.ConnectionID == "" || session.TenantID == "" || session.Version < 1 {
		return false, nil
	}
	const q = `SELECT c.provider_id, c.status, c.token_access_mode, c.token_encrypted,
		p.enabled, p.auth_url, p.token_url, b.version, b.api_origin, b.path_prefix, b.method, b.reviewed_by
		FROM oauth_connections c JOIN oauth_providers p ON p.provider_id=c.provider_id
		JOIN oauth_api_policies b ON b.connection_id=c.id AND b.tenant_id=c.tenant_id
		WHERE c.id=$1 AND c.tenant_id=$2`
	var providerID, status, mode, origin, prefix, method, reviewer, authURL, tokenURL string
	var enc []byte
	var enabled any
	var version int64
	err := s.db.QueryRowContext(ctx, s.bind(q), session.ConnectionID, session.TenantID).Scan(
		&providerID, &status, &mode, &enc, &enabled, &authURL, &tokenURL, &version, &origin, &prefix, &method, &reviewer)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrap("recheck broker policy", err)
	}
	return providerID == session.ProviderID && status == "connected" && mode == "broker_only" &&
		parseBool(enabled) && rawTokenAllowedForProvider(providerID, authURL, tokenURL) &&
		version == session.Version && origin == session.APIOrigin &&
		prefix == session.PathPrefix && method == session.Method && reviewer == session.ReviewedBy &&
		sha256.Sum256(enc) == session.tokenCipherHash, nil
}

// ConnectionActive is the cheap final status/provider-enabled fence for the
// canonical Salesforce route, including edits committed during permit wait.
func (s *Store) ConnectionActive(ctx context.Context, tenantID, connectionID, providerID string) (bool, error) {
	if tenantID == "" || connectionID == "" || providerID == "" {
		return false, nil
	}
	const q = `SELECT c.status, p.enabled FROM oauth_connections c
		JOIN oauth_providers p ON p.provider_id=c.provider_id
		WHERE c.id=$1 AND c.tenant_id=$2 AND c.provider_id=$3`
	var status string
	var enabled any
	err := s.db.QueryRowContext(ctx, s.bind(q), connectionID, tenantID, providerID).Scan(&status, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrap("recheck OAuth connection status", err)
	}
	return status == "connected" && parseBool(enabled), nil
}
