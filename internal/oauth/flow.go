package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/vault"
)

// stateTTL bounds how long an authorize->callback round trip may take.
const stateTTL = 10 * time.Minute

const maxAuthorizeURLBytes = 16 << 10

// StartAuth begins the authorization-code flow: it records CSRF + PKCE state
// and returns the provider authorize URL to redirect the user to. The provider
// must be enabled and configured with a client id.
func (s *Store) StartAuth(ctx context.Context, tenantID, providerID, name, redirectURI, createdBy string) (string, error) {
	p, err := s.GetProvider(ctx, providerID)
	if err != nil {
		return "", err
	}
	if !p.Enabled || p.ClientID == "" {
		return "", errors.New("oauth: provider is not configured (needs client id + enabled)")
	}
	if name == "" {
		return "", errors.New("oauth: a connection name is required")
	}
	redirectURI = strings.TrimSpace(redirectURI)
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("oauth: redirect URI must be an absolute callback without userinfo, query, or fragment")
	}
	s.gcStates(ctx)

	state := newID("st_")
	verifier := randString(48)
	challenge := pkceChallenge(verifier)

	scopes := p.Scopes
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", p.ClientID)
	v.Set("redirect_uri", redirectURI)
	if scopes != "" {
		v.Set("scope", scopes)
	}
	v.Set("state", state)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	// Ask for a refresh token on providers that gate it (Google).
	v.Set("access_type", "offline")
	v.Set("prompt", "consent")
	// Provider-specific authorize params (e.g. Notion's owner=user).
	for k, val := range s.profile(providerID).AuthParams {
		v.Set(k, val)
	}
	sep := "?"
	if strings.Contains(p.AuthURL, "?") {
		sep = "&"
	}
	authURL := p.AuthURL + sep + v.Encode()
	if len(authURL) > maxAuthorizeURLBytes {
		return "", errors.New("oauth: authorization URL exceeds the size limit")
	}
	const q = `INSERT INTO oauth_states (state, tenant_id, provider_id, name, redirect_uri, code_verifier, created_by, created_at, requested_scopes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	if _, err := s.db.ExecContext(ctx, s.bind(q),
		state, tenantID, providerID, name, redirectURI, verifier, createdBy, s.nowVal(), scopes); err != nil {
		return "", wrap("save state", err)
	}
	return authURL, nil
}

// CompleteAuth handles the provider redirect back: it validates + consumes the
// state, exchanges the code for tokens, and stores an encrypted connection.
func (s *Store) CompleteAuth(ctx context.Context, state, code string) (Connection, error) {
	if state == "" || code == "" {
		return Connection{}, errors.New("oauth: missing state or code")
	}
	var (
		tenantID, providerID, name, redirectURI, verifier, createdBy, requestedScopes string
		createdAny                                                                    any
	)
	// Consume the state in the same statement that reads it. A SELECT followed
	// by DELETE lets concurrent callbacks exchange the same authorization code.
	const consume = `DELETE FROM oauth_states WHERE state = $1
		RETURNING tenant_id, provider_id, name, redirect_uri, code_verifier, created_by, created_at, requested_scopes`
	err := s.db.QueryRowContext(ctx, s.bind(consume), state).
		Scan(&tenantID, &providerID, &name, &redirectURI, &verifier, &createdBy, &createdAny, &requestedScopes)
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, errors.New("oauth: unknown or expired state")
	}
	if err != nil {
		return Connection{}, wrap("load state", err)
	}
	if created := s.parseTime(createdAny); created.IsZero() || s.now().UTC().Sub(created) > stateTTL {
		return Connection{}, errors.New("oauth: state expired, restart the connection")
	}

	p, err := s.GetProvider(ctx, providerID)
	if err != nil {
		return Connection{}, err
	}
	if !p.Enabled {
		return Connection{}, errors.New("oauth: provider disabled before callback")
	}
	tok, err := s.exchange(ctx, p, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		return Connection{}, err
	}
	return s.upsertConnectionWithRequestedScopes(ctx, tenantID, providerID, name, createdBy, tok, requestedScopes)
}

// Token returns a valid access token for a connection, refreshing it first if
// it is expired (or about to be) and a refresh token is available. tenantID, if
// non-empty, guards against cross-tenant access. This host-internal accessor
// is used by the Salesforce and reviewed generic host brokers. Workflow and command token release must
// use RawToken, which checks the provider policy against the current row.
func (s *Store) Token(ctx context.Context, connectionID, tenantID string) (string, error) {
	return s.token(ctx, connectionID, tenantID, false)
}

func (s *Store) token(ctx context.Context, connectionID, tenantID string, refreshLocked bool) (string, error) {
	q := `SELECT id, tenant_id, provider_id, name, token_encrypted FROM oauth_connections WHERE id = $1`
	args := []any{connectionID}
	if tenantID != "" {
		q += ` AND tenant_id = $2`
		args = append(args, tenantID)
	}
	var id, ten, providerID, name string
	var enc []byte
	err := s.db.QueryRowContext(ctx, s.bind(q), args...).Scan(&id, &ten, &providerID, &name, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", wrap("load connection", err)
	}
	identity := connectionTokenIdentity(ten, providerID, name)
	legacy := len(enc) > 0 && enc[0] == vault.VersionV1
	tb, err := s.loadTokenBlob(enc, identity)
	if err != nil {
		return "", fmt.Errorf("oauth: decrypt token: %w", err)
	}
	if legacy {
		if migrated, mErr := s.saveTokenBlob(identity, tb); mErr == nil {
			// Do not overwrite a newer refresh or a human reconnect while lazily
			// migrating an old ciphertext.
			if res, updateErr := s.db.ExecContext(ctx, s.bind(`UPDATE oauth_connections SET token_encrypted=$1, updated_at=$2 WHERE id=$3 AND token_encrypted=$4`), migrated, s.nowVal(), id, enc); updateErr == nil {
				if changed, rowsErr := res.RowsAffected(); rowsErr == nil && changed == 1 {
					enc = migrated
				}
			}
		}
	}
	// Fresh enough? (60s skew guard.)
	if tb.Expiry.IsZero() || s.now().UTC().Before(tb.Expiry.Add(-60*time.Second)) {
		return tb.AccessToken, nil
	}
	if !refreshLocked {
		// Re-read under a connection-specific lock. Another worker may already
		// have rotated the refresh token after our first read. Postgres uses a
		// distributed advisory lock; SQLite uses a local gate because SQLite
		// deployments have a single daemon process.
		return s.withRefreshLock(ctx, id, func() (string, error) {
			return s.token(ctx, connectionID, tenantID, true)
		})
	}
	if tb.RefreshToken == "" {
		// The access token is expired or inside the safety window. Returning it
		// would violate Token's valid-token contract and make the workflow fail
		// later with a less actionable provider error.
		res, markErr := s.db.ExecContext(ctx, s.bind(`UPDATE oauth_connections SET status='error', updated_at=$1 WHERE id=$2 AND tenant_id=$3 AND token_encrypted=$4`), s.nowVal(), id, ten, enc)
		if markErr != nil {
			return "", wrap("mark expired connection", markErr)
		}
		changed, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return "", wrap("mark expired connection", rowsErr)
		}
		if changed == 0 {
			return s.currentTokenAfterRefreshRace(ctx, id, ten, identity)
		}
		return "", errors.New("oauth: access token expired or expiring without a refresh token; reconnect the account")
	}
	p, err := s.GetProvider(ctx, providerID)
	if err != nil {
		return "", err
	}
	refreshed, err := s.exchange(ctx, p, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tb.RefreshToken},
	})
	if err != nil {
		// A different caller may have refreshed or reconnected this account
		// while the provider request was in flight. Never mark that newer row
		// broken because an old refresh token failed.
		res, markErr := s.db.ExecContext(ctx, s.bind(`UPDATE oauth_connections SET status='error', updated_at=$1 WHERE id=$2 AND tenant_id=$3 AND token_encrypted=$4`), s.nowVal(), id, ten, enc)
		if markErr == nil {
			if changed, rowsErr := res.RowsAffected(); rowsErr == nil && changed == 0 {
				return s.currentTokenAfterRefreshRace(ctx, id, ten, identity)
			}
		}
		return "", err
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = tb.RefreshToken // providers often omit it on refresh
	}
	if refreshed.Scope == "" {
		refreshed.Scope = tb.Scope // an omitted scope does not revoke the grant
	}
	if refreshed.TokenType == "" {
		refreshed.TokenType = tb.TokenType
	}
	if providerID == "salesforce" {
		if refreshed.SalesforceAPIOrigin == "" {
			// Salesforce normally includes instance_url on refresh. Keep the
			// validated origin from the prior token if an exchange omits it.
			refreshed.SalesforceAPIOrigin = tb.SalesforceAPIOrigin
		}
		if refreshed.SalesforceOrgID == "" {
			refreshed.SalesforceOrgID = tb.SalesforceOrgID
		} else if tb.SalesforceOrgID != "" && refreshed.SalesforceOrgID != tb.SalesforceOrgID {
			// A refresh cannot silently move a connection to another org.
			// Reconnecting is the explicit way to change the account.
			return "", errors.New("oauth: Salesforce organization changed during refresh; reconnect the account")
		}
	}
	newEnc, err := s.saveTokenBlob(identity, refreshed)
	if err != nil {
		return "", err
	}
	// Compare-and-swap the exact row read above. Refresh must neither
	// resurrect a deleted connection nor replace a newer rotated token.
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE oauth_connections
		SET token_encrypted=$1, expires_at=$2, scopes=$3, status='connected', updated_at=$4
		WHERE id=$5 AND tenant_id=$6 AND token_encrypted=$7`),
		newEnc, s.timeVal(refreshed.Expiry), refreshed.Scope, s.nowVal(), id, ten, enc)
	if err != nil {
		return "", wrap("save refreshed token", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return "", wrap("save refreshed token", err)
	}
	if changed == 0 {
		return s.currentTokenAfterRefreshRace(ctx, id, ten, identity)
	}
	return refreshed.AccessToken, nil
}

func (s *Store) withRefreshLock(ctx context.Context, id string, fn func() (string, error)) (string, error) {
	if s.engine == EnginePostgres {
		// The lock is transaction-scoped, so cancellation/rollback releases it
		// even if the provider request fails. No OAuth row lock is held during
		// network I/O; a reconnect can proceed and the ciphertext CAS below
		// prevents its new token from being overwritten.
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return "", wrap("start refresh lock", err)
		}
		defer tx.Rollback()
		sum := sha256.Sum256([]byte("reactor-oauth-refresh\x00" + id))
		key := int64(binary.BigEndian.Uint64(sum[:8]))
		var ignored any
		if err := tx.QueryRowContext(ctx, `SELECT pg_advisory_xact_lock($1)`, key).Scan(&ignored); err != nil {
			return "", wrap("acquire refresh lock", err)
		}
		return fn()
	}
	s.refreshMu.Lock()
	if s.refreshGates == nil {
		s.refreshGates = make(map[string]*refreshGate)
	}
	gate := s.refreshGates[id]
	if gate == nil {
		gate = &refreshGate{semaphore: make(chan struct{}, 1)}
		s.refreshGates[id] = gate
	}
	gate.users++
	s.refreshMu.Unlock()
	releaseUser := func() {
		s.refreshMu.Lock()
		gate.users--
		if gate.users == 0 {
			delete(s.refreshGates, id)
		}
		s.refreshMu.Unlock()
	}
	select {
	case gate.semaphore <- struct{}{}:
		defer func() {
			<-gate.semaphore
			releaseUser()
		}()
		return fn()
	case <-ctx.Done():
		releaseUser()
		return "", ctx.Err()
	}
}

// currentTokenAfterRefreshRace returns the winner of a concurrent refresh or
// reconnect only when that token is fresh. A deleted connection stays deleted,
// and an unresolved expired-token race asks the caller to retry instead of
// returning a token known to be stale.
func (s *Store) currentTokenAfterRefreshRace(ctx context.Context, id, tenantID, identity string) (string, error) {
	var enc []byte
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT token_encrypted FROM oauth_connections WHERE id=$1 AND tenant_id=$2`), id, tenantID).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", wrap("load refreshed connection", err)
	}
	tb, err := s.loadTokenBlob(enc, identity)
	if err != nil {
		return "", fmt.Errorf("oauth: decrypt refreshed token: %w", err)
	}
	if !tb.Expiry.IsZero() && !s.now().UTC().Before(tb.Expiry.Add(-60*time.Second)) {
		return "", errors.New("oauth: connection changed during refresh; retry")
	}
	return tb.AccessToken, nil
}

const maxTokenResponseBytes = 1 << 20

// exchange POSTs to the provider token endpoint and parses the token response.
func (s *Store) exchange(ctx context.Context, p Provider, form url.Values) (tokenBlob, error) {
	basic := s.profile(p.ProviderID).TokenAuthStyle == "basic"
	// Client id is always safe in the body (identifies the app). The secret
	// goes either in the body (default) or an HTTP Basic header (when the
	// provider requires it, e.g. Pipedrive, Notion).
	form.Set("client_id", p.ClientID)
	if p.ClientSecret != "" && !basic {
		form.Set("client_secret", p.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenBlob{}, wrap("token request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic && p.ClientSecret != "" {
		req.SetBasicAuth(p.ClientID, p.ClientSecret)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return tokenBlob{}, wrap("token exchange", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Status code only. Echoing the body put the token endpoint's response
		// into an operator-visible error, which turns any SSRF reach (a
		// redirect, or an internal token_url) into a read primitive. Same
		// reason the Slack and webhook notifiers report status alone.
		return tokenBlob{}, fmt.Errorf("oauth: token endpoint returned %d", resp.StatusCode)
	}
	// Parse only complete responses. Both JSON with trailing whitespace and
	// form-encoded tokens can remain valid when truncated at the byte limit.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if readErr != nil {
		// Do not expose response bytes or transport-provided error text: these
		// errors reach the operator and may contain credential material.
		return tokenBlob{}, errors.New("oauth: could not read token response")
	}
	if len(body) > maxTokenResponseBytes {
		return tokenBlob{}, fmt.Errorf("oauth: token response exceeds %d-byte limit", maxTokenResponseBytes)
	}
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int64  `json:"expires_in"`
		InstanceURL  string `json:"instance_url"`
		IdentityURL  string `json:"id"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.AccessToken == "" {
		// Some providers reply form-encoded; fall back.
		if vals, perr := url.ParseQuery(string(body)); perr == nil && vals.Get("access_token") != "" {
			raw.AccessToken = vals.Get("access_token")
			raw.RefreshToken = vals.Get("refresh_token")
			raw.TokenType = vals.Get("token_type")
			raw.Scope = vals.Get("scope")
			raw.InstanceURL = vals.Get("instance_url")
			raw.IdentityURL = vals.Get("id")
		} else {
			return tokenBlob{}, fmt.Errorf("oauth: token response had no access_token")
		}
	}
	tb := tokenBlob{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
		Scope:        raw.Scope,
	}
	if p.ProviderID == "salesforce" {
		if raw.InstanceURL == "" && form.Get("grant_type") != "refresh_token" {
			return tokenBlob{}, errors.New("oauth: Salesforce token response omitted instance_url")
		}
		if raw.InstanceURL != "" {
			origin, err := validateSalesforceAPIOrigin(raw.InstanceURL)
			if err != nil {
				return tokenBlob{}, err
			}
			tb.SalesforceAPIOrigin = origin
		}
		if raw.IdentityURL != "" {
			orgID, err := salesforceOrgFromIdentityURL(raw.IdentityURL)
			if err != nil {
				return tokenBlob{}, err
			}
			tb.SalesforceOrgID = orgID
		}
	}
	if raw.ExpiresIn > 0 {
		tb.Expiry = s.now().UTC().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return tb, nil
}

func (s *Store) upsertConnection(ctx context.Context, tenantID, providerID, name, createdBy string, tok tokenBlob) (Connection, error) {
	return s.upsertConnectionWithRequestedScopes(ctx, tenantID, providerID, name, createdBy, tok, "")
}

func (s *Store) upsertConnectionWithRequestedScopes(ctx context.Context, tenantID, providerID, name, createdBy string, tok tokenBlob, requestedScopes string) (Connection, error) {
	// OAuth token responses may omit scope when the grant matches the exact
	// request. Persist the scopes actually requested at StartAuth, never the
	// provider's possibly edited value at callback. Old pending states have
	// no snapshot and therefore cannot enter the mail broker.
	if tok.Scope == "" && requestedScopes != "" {
		tok.Scope = requestedScopes
	}
	identity := connectionTokenIdentity(tenantID, providerID, name)
	enc, err := s.saveTokenBlob(identity, tok)
	if err != nil {
		return Connection{}, fmt.Errorf("oauth: encrypt token: %w", err)
	}
	id := newID("conn_")
	accessMode := "broker_only"
	legacyReason := ""
	// New Google and Microsoft connections use the host-owned mail broker.
	// ON CONFLICT below intentionally keeps the stored mode for an existing
	// legacy_raw/email_adapter row until its approved workflows migrate.
	const q = `INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, expires_at, scopes, status, created_by, updated_at, token_access_mode, legacy_raw_reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'connected',$8,$9,$10,$11)
		ON CONFLICT (tenant_id, provider_id, name) DO UPDATE SET
			token_encrypted=excluded.token_encrypted, expires_at=excluded.expires_at,
			scopes=excluded.scopes, status='connected', updated_at=excluded.updated_at
		RETURNING id, created_by, created_at, token_access_mode`
	var storedID, storedCreator, storedMode string
	var createdAny any
	if err := s.db.QueryRowContext(ctx, s.bind(q),
		id, tenantID, providerID, name, enc, s.timeVal(tok.Expiry), tok.Scope, createdBy, s.nowVal(), accessMode, legacyReason).Scan(&storedID, &storedCreator, &createdAny, &storedMode); err != nil {
		return Connection{}, wrap("save connection", err)
	}
	return Connection{ID: storedID, TenantID: tenantID, ProviderID: providerID, Name: name,
		Scopes: tok.Scope, Status: "connected", TokenAccessMode: storedMode,
		ExpiresAt: tok.Expiry, CreatedBy: storedCreator,
		CreatedAt: s.parseTime(createdAny)}, nil
}

func (s *Store) gcStates(ctx context.Context) {
	cutoff := s.timeVal(s.now().UTC().Add(-stateTTL))
	_, _ = s.db.ExecContext(ctx, s.bind(`DELETE FROM oauth_states WHERE created_at < $1`), cutoff)
}

func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic; never emit a predictable
		// OAuth state / PKCE verifier from a zeroed buffer.
		panic("oauth: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
