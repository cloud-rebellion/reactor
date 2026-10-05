// Package oauth manages OAuth2 connections: operator-configured providers and
// per-tenant connected accounts whose tokens are encrypted at rest with the
// master key. Workflows fetch a fresh access token by connection id without
// ever handling the OAuth dance or the raw refresh token.
package oauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/reactor/internal/safehttp"
	"github.com/bright-interaction/reactor/internal/vault"
)

// secureURL allows https anywhere, or http only on loopback (local dev/tests).
func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// Engine selects the SQL dialect for the engine-portable queries.
type Engine int

const (
	EngineSQLite Engine = iota
	EnginePostgres
)

// ErrNotFound is returned when a provider or connection id doesn't resolve.
var ErrNotFound = errors.New("oauth: not found")

// Provider is an operator-configured OAuth2 client app.
type Provider struct {
	ProviderID   string
	Name         string
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string // decrypted only in memory; never serialized to the UI
	Scopes       string
	Enabled      bool
	HasSecret    bool
}

// Connection is a connected account for a tenant.
type Connection struct {
	ID         string
	TenantID   string
	ProviderID string
	Name       string
	Scopes     string
	Status     string
	// TokenAccessMode is legacy_raw or broker_only. A broker-only connection
	// needs a reviewed API policy before generic GETs can execute.
	TokenAccessMode     string
	BrokerPolicyVersion int64
	ExpiresAt           time.Time
	CreatedBy           string
	CreatedAt           time.Time
}

// tokenBlob is the encrypted payload of a connection.
type tokenBlob struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	// SalesforceAPIOrigin is provider-returned account metadata, not a URL
	// supplied by an MCP caller or workflow. It stays in the encrypted blob.
	SalesforceAPIOrigin string `json:"salesforce_api_origin,omitempty"`
	// SalesforceOrgID comes from the provider's OAuth identity URL. The
	// broker hashes this stable identity to share a budget across connections.
	SalesforceOrgID string `json:"salesforce_org_id,omitempty"`
}

// Store persists providers + connections and runs the OAuth2 flow.
type Store struct {
	db        *sql.DB
	engine    Engine
	masterKey []byte
	http      *http.Client
	now       func() time.Time

	// SQLite is a single-process deployment. Its per-connection gates avoid
	// duplicate rotating-token refreshes without holding the database writer
	// lock across a provider request. Postgres uses an advisory transaction
	// lock for the same fence across distributed workers.
	refreshMu    sync.Mutex
	refreshGates map[string]*refreshGate

	// ProfileFor optionally returns per-provider OAuth quirks (token-exchange
	// auth style, extra authorize params) so the generic flow can talk to
	// providers that deviate from the plain spec. The daemon wires this to the
	// service catalog; nil means the default behaviour (creds in the body).
	ProfileFor func(providerID string) Profile
}

type refreshGate struct {
	semaphore chan struct{}
	users     int
}

// Profile holds the optional, provider-specific knobs the OAuth flow honours.
// It keeps this package free of the catalog: the caller supplies a resolver.
type Profile struct {
	// TokenAuthStyle == "basic" sends the client id/secret as an HTTP Basic
	// header on the token request (required by Pipedrive, Notion, ...). Any
	// other value (including "") puts them in the form body, the prior default.
	TokenAuthStyle string
	// AuthParams are extra query parameters added to the authorize URL (e.g.
	// Notion's owner=user).
	AuthParams map[string]string
}

func (s *Store) profile(providerID string) Profile {
	if s.ProfileFor != nil {
		return s.ProfileFor(providerID)
	}
	return Profile{}
}

// New builds a Store. masterKey must be 32 bytes (the same key the vault uses).
func New(db *sql.DB, engine Engine, masterKey []byte) *Store {
	return &Store{
		db:        db,
		engine:    engine,
		masterKey: masterKey,
		// safehttp, not a bare client: it refuses redirects (so a hostile or
		// compromised provider cannot 302 the token request into the internal
		// network) and always blocks link-local, which includes the cloud
		// metadata endpoint. allowPrivate is true because secureURL
		// deliberately permits an http provider on loopback for self-hosted
		// and local-dev setups; the metadata block holds either way.
		http: safehttp.Client(true),
		now:  time.Now,
	}
}

func (s *Store) bind(q string) string {
	if s.engine != EngineSQLite {
		return q
	}
	out := make([]byte, 0, len(q))
	for i := 0; i < len(q); i++ {
		if q[i] == '$' && i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
			out = append(out, '?')
			i++
			for i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
				i++
			}
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

func (s *Store) nowVal() any {
	if s.engine == EngineSQLite {
		return s.now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return s.now().UTC()
}

func (s *Store) timeVal(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	if s.engine == EngineSQLite {
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return t.UTC()
}

func (s *Store) boolVal(b bool) any {
	if s.engine == EngineSQLite {
		if b {
			return 1
		}
		return 0
	}
	return b
}

func parseBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case []byte:
		return len(x) == 1 && x[0] == 't'
	case string:
		return x == "t" || x == "true" || x == "1"
	}
	return false
}

func (s *Store) parseTime(v any) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		for _, layout := range []string{"2006-01-02T15:04:05.000Z", time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, x); err == nil {
				return t.UTC()
			}
		}
	case []byte:
		return s.parseTime(string(x))
	}
	return time.Time{}
}

// providerSecretIdentity and connectionTokenIdentity are stable, non-secret
// associated-data labels for encrypted OAuth rows. Length-prefixing each
// field avoids delimiter ambiguity if an operator uses an unusual id/name.
func providerSecretIdentity(providerID string) string {
	return oauthCipherIdentity("provider-secret", providerID)
}

func connectionTokenIdentity(tenantID, providerID, name string) string {
	return oauthCipherIdentity("connection-token", tenantID, providerID, name)
}

func oauthCipherIdentity(kind string, fields ...string) string {
	var b strings.Builder
	b.WriteString("reactor-oauth-v1\x00")
	b.WriteString(kind)
	for _, field := range fields {
		fmt.Fprintf(&b, "\x00%d:", len(field))
		b.WriteString(field)
	}
	return b.String()
}

func newID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("oauth: crypto/rand failed: " + err.Error())
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// --- Provider CRUD -------------------------------------------------------

// UpsertProvider creates or updates a provider. A non-empty clientSecret is
// encrypted; an empty one leaves the stored secret untouched on update.
func (s *Store) UpsertProvider(ctx context.Context, p Provider, clientSecret string) error {
	if !secureURL(p.AuthURL) || !secureURL(p.TokenURL) {
		return errors.New("oauth: auth_url and token_url must be https (or http on localhost)")
	}
	if p.ProviderID != "salesforce" &&
		(isKnownSalesforceOAuthEndpoint(p.AuthURL) || isKnownSalesforceOAuthEndpoint(p.TokenURL)) {
		return errors.New("oauth: Salesforce OAuth endpoints require the canonical salesforce provider id")
	}
	var enc []byte
	if clientSecret != "" {
		if len(clientSecret) > vault.MaxSecretBytes {
			return vault.ErrSecretTooLarge
		}
		e, err := vault.EncryptForID(s.masterKey, providerSecretIdentity(p.ProviderID), []byte(clientSecret))
		if err != nil {
			return fmt.Errorf("oauth: encrypt client secret: %w", err)
		}
		enc = e
	}
	// Two paths so an update without a new secret keeps the old one.
	if enc != nil {
		const q = `INSERT INTO oauth_providers
			(provider_id, name, auth_url, token_url, client_id, client_secret_encrypted, scopes, enabled, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (provider_id) DO UPDATE SET
				name=excluded.name, auth_url=excluded.auth_url, token_url=excluded.token_url,
				client_id=excluded.client_id, client_secret_encrypted=excluded.client_secret_encrypted,
				scopes=excluded.scopes, enabled=excluded.enabled, updated_at=excluded.updated_at`
		_, err := s.db.ExecContext(ctx, s.bind(q),
			p.ProviderID, p.Name, p.AuthURL, p.TokenURL, p.ClientID, enc, p.Scopes, s.boolVal(p.Enabled), s.nowVal())
		return wrap("upsert provider", err)
	}
	const q = `INSERT INTO oauth_providers
		(provider_id, name, auth_url, token_url, client_id, scopes, enabled, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (provider_id) DO UPDATE SET
			name=excluded.name, auth_url=excluded.auth_url, token_url=excluded.token_url,
			client_id=excluded.client_id, scopes=excluded.scopes, enabled=excluded.enabled,
			updated_at=excluded.updated_at`
	_, err := s.db.ExecContext(ctx, s.bind(q),
		p.ProviderID, p.Name, p.AuthURL, p.TokenURL, p.ClientID, p.Scopes, s.boolVal(p.Enabled), s.nowVal())
	return wrap("upsert provider", err)
}

// GetProvider returns a provider with its client secret decrypted (for the
// flow). Returns ErrNotFound for an unknown id.
func (s *Store) GetProvider(ctx context.Context, id string) (Provider, error) {
	const q = `SELECT provider_id, name, auth_url, token_url, client_id, client_secret_encrypted, scopes, enabled
		FROM oauth_providers WHERE provider_id = $1`
	var (
		p    Provider
		enc  []byte
		enab any
	)
	err := s.db.QueryRowContext(ctx, s.bind(q), id).
		Scan(&p.ProviderID, &p.Name, &p.AuthURL, &p.TokenURL, &p.ClientID, &enc, &p.Scopes, &enab)
	if errors.Is(err, sql.ErrNoRows) {
		return Provider{}, ErrNotFound
	}
	if err != nil {
		return Provider{}, wrap("get provider", err)
	}
	p.Enabled = parseBool(enab)
	p.HasSecret = len(enc) > 0
	if len(enc) > 0 {
		dec, derr := vault.DecryptForID(s.masterKey, providerSecretIdentity(id), enc)
		if derr != nil {
			return Provider{}, fmt.Errorf("oauth: decrypt client secret: %w", derr)
		}
		if len(dec) > vault.MaxSecretBytes {
			for i := range dec {
				dec[i] = 0
			}
			return Provider{}, vault.ErrSecretTooLarge
		}
		// v1 rows were encrypted without provider identity. Keep them readable
		// during migration, then write the authenticated v2 form best-effort.
		if enc[0] == vault.VersionV1 {
			if migrated, mErr := vault.EncryptForID(s.masterKey, providerSecretIdentity(id), dec); mErr == nil {
				_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE oauth_providers SET client_secret_encrypted=$1, updated_at=$2 WHERE provider_id=$3`), migrated, s.nowVal(), id)
			}
		}
		p.ClientSecret = string(dec)
		for i := range dec {
			dec[i] = 0
		}
	}
	return p, nil
}

// ListProviders returns all providers WITHOUT decrypting secrets (HasSecret
// only). For the admin UI.
func (s *Store) ListProviders(ctx context.Context) ([]Provider, error) {
	const q = `SELECT provider_id, name, auth_url, token_url, client_id,
		(client_secret_encrypted IS NOT NULL), scopes, enabled
		FROM oauth_providers ORDER BY provider_id`
	rows, err := s.db.QueryContext(ctx, s.bind(q))
	if err != nil {
		return nil, wrap("list providers", err)
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		var hasSecret, enab any
		if err := rows.Scan(&p.ProviderID, &p.Name, &p.AuthURL, &p.TokenURL, &p.ClientID, &hasSecret, &p.Scopes, &enab); err != nil {
			return nil, err
		}
		p.HasSecret = parseBool(hasSecret)
		p.Enabled = parseBool(enab)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteProvider removes a provider (and its connections via FK cascade).
func (s *Store) DeleteProvider(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM oauth_providers WHERE provider_id = $1`), id)
	return wrap("delete provider", err)
}

// --- Connection reads ----------------------------------------------------

// ListConnections returns a tenant's connections (no tokens). Pass "" for all
// (admin).
func (s *Store) ListConnections(ctx context.Context, tenantID string) ([]Connection, error) {
	q := `SELECT c.id, c.tenant_id, c.provider_id, c.name, c.scopes, c.status, c.token_access_mode,
		COALESCE((SELECT version FROM oauth_api_policies p WHERE p.connection_id=c.id AND p.tenant_id=c.tenant_id),0),
		c.expires_at, c.created_by, c.created_at FROM oauth_connections c`
	var args []any
	if tenantID != "" {
		q += ` WHERE c.tenant_id = $1`
		args = append(args, tenantID)
	}
	q += ` ORDER BY c.provider_id, c.name`
	rows, err := s.db.QueryContext(ctx, s.bind(q), args...)
	if err != nil {
		return nil, wrap("list connections", err)
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		c, err := s.scanConn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListConnectionsPage returns one bounded page of connections. The tenant and
// optional provider filter are applied in SQL so callers do not have to load
// the complete connection inventory before paging it. The extra row is used
// only to report whether another page exists; connection tokens are never
// selected by this query.
func (s *Store) ListConnectionsPage(ctx context.Context, tenantID, providerID string, limit, offset int) ([]Connection, bool, error) {
	if limit <= 0 || limit > 500 || offset < 0 || offset > 10000 {
		return nil, false, errors.New("oauth: invalid connection page")
	}
	q := `SELECT c.id, c.tenant_id, c.provider_id, c.name, c.scopes, c.status, c.token_access_mode,
		COALESCE((SELECT version FROM oauth_api_policies p WHERE p.connection_id=c.id AND p.tenant_id=c.tenant_id),0),
		c.expires_at, c.created_by, c.created_at FROM oauth_connections c`
	args := make([]any, 0, 4)
	position := 1
	where := make([]string, 0, 2)
	if tenantID != "" {
		where = append(where, fmt.Sprintf("c.tenant_id = $%d", position))
		args = append(args, tenantID)
		position++
	}
	if providerID != "" {
		where = append(where, fmt.Sprintf("c.provider_id = $%d", position))
		args = append(args, providerID)
		position++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY c.provider_id, c.name, c.id LIMIT $%d OFFSET $%d", position, position+1)
	args = append(args, limit+1, offset)
	rows, err := s.db.QueryContext(ctx, s.bind(q), args...)
	if err != nil {
		return nil, false, wrap("list connection page", err)
	}
	defer rows.Close()
	out := make([]Connection, 0, limit)
	hasMore := false
	for rows.Next() {
		if len(out) == limit {
			hasMore = true
			break
		}
		c, scanErr := s.scanConn(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, hasMore, nil
}

type rowScanner interface{ Scan(...any) error }

func (s *Store) scanConn(r rowScanner) (Connection, error) {
	var c Connection
	var expires, created any
	if err := r.Scan(&c.ID, &c.TenantID, &c.ProviderID, &c.Name, &c.Scopes, &c.Status,
		&c.TokenAccessMode, &c.BrokerPolicyVersion, &expires, &c.CreatedBy, &created); err != nil {
		return Connection{}, err
	}
	c.ExpiresAt = s.parseTime(expires)
	c.CreatedAt = s.parseTime(created)
	return c, nil
}

// DeleteConnection removes a connection. tenantID guards cross-tenant deletes
// ("" = no guard, admin).
func (s *Store) DeleteConnection(ctx context.Context, id, tenantID string) error {
	q := `DELETE FROM oauth_connections WHERE id = $1`
	args := []any{id}
	if tenantID != "" {
		q += ` AND tenant_id = $2`
		args = append(args, tenantID)
	}
	res, err := s.db.ExecContext(ctx, s.bind(q), args...)
	if err != nil {
		return wrap("delete connection", err)
	}
	if affected, err := res.RowsAffected(); err != nil {
		return wrap("delete connection", err)
	} else if affected == 0 {
		// Keep a foreign tenant indistinguishable from an unknown id. Callers
		// can safely retry after re-reading their own inventory without learning
		// whether another tenant owns the connection.
		return ErrNotFound
	}
	return nil
}

// ConnectionTenant returns the owner tenant for an admin-selected connection.
// Approval handlers derive scope from this row, never from a posted tenant id.
func (s *Store) ConnectionTenant(ctx context.Context, connectionID string) (string, error) {
	if connectionID == "" {
		return "", ErrNotFound
	}
	var tenantID string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT tenant_id FROM oauth_connections WHERE id=$1`), connectionID).Scan(&tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return tenantID, wrap("load connection tenant", err)
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("oauth: %s: %w", op, err)
}

func (s *Store) saveTokenBlob(identity string, tb tokenBlob) ([]byte, error) {
	if tb.SalesforceAPIOrigin != "" {
		origin, err := validateSalesforceAPIOrigin(tb.SalesforceAPIOrigin)
		if err != nil {
			return nil, err
		}
		tb.SalesforceAPIOrigin = origin
	}
	if tb.SalesforceOrgID != "" {
		if !validSalesforceOrgID(tb.SalesforceOrgID) {
			return nil, errors.New("oauth: invalid Salesforce organization identity")
		}
		// The provider can use either the 15- or 18-character representation.
		// Store one canonical form so refresh comparisons keep the same bucket.
		tb.SalesforceOrgID = tb.SalesforceOrgID[:15]
	}
	raw, err := json.Marshal(tb)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	return vault.EncryptForID(s.masterKey, identity, raw)
}

func (s *Store) loadTokenBlob(enc []byte, identity ...string) (tokenBlob, error) {
	var (
		raw []byte
		err error
	)
	if len(enc) > 0 && enc[0] == vault.VersionV2 {
		if len(identity) != 1 || identity[0] == "" {
			return tokenBlob{}, errors.New("oauth: connection identity required for token blob")
		}
		raw, err = vault.DecryptForID(s.masterKey, identity[0], enc)
	} else {
		raw, err = vault.Decrypt(s.masterKey, enc)
	}
	if err != nil {
		return tokenBlob{}, err
	}
	var tb tokenBlob
	err = json.Unmarshal(raw, &tb)
	for i := range raw {
		raw[i] = 0
	}
	return tb, err
}
