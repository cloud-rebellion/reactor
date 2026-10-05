// Package auth owns user identity, sessions, and API tokens for the
// dashboard. Sits next to internal/credentials (which is a separate
// concept: third-party API keys for workflow code) so the boundary is
// "auth is for humans signing in; credentials are for workflows
// signing OUT to APIs."
//
// The store interface is engine-portable (sqlite + postgres share one
// shape); a *sql.DB is passed in at construction.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/argon2"
)

// Role enumerates the per-user authorisation level. Phase 1 ships
// admin + member; later phases add per-team membership.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// User is the row from the users table.
type User struct {
	ID          string
	Username    string
	PasswordPHC string // argon2id PHC (or legacy lowercase hex sha256)
	Role        Role
	TenantID    string // the tenant this user belongs to (scopes their dashboard)
	Disabled    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastLoginAt *time.Time
}

// IsAdmin is the canonical role check; isolated as a method so future
// per-team admin scopes can re-implement without touching call sites.
func (u User) IsAdmin() bool { return u.Role == RoleAdmin }

// Session is a server-side row for a browser cookie. id_hash is the
// sha256 hex of the cookie value the browser sent; storing the hash
// (not the raw value) means a database snapshot does not yield
// session theft.
type Session struct {
	IDHash     string
	UserID     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	UserAgent  string
	IP         string
}

// APIToken is a personal access token for programmatic clients. The
// raw token is shown to the user exactly once at mint time; the row
// stores the sha256 hex hash.
type APIToken struct {
	ID         string
	UserID     string
	Name       string
	TokenHash  string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	Revoked    bool
}

// Common errors.
var (
	ErrNotFound        = errors.New("auth: not found")
	ErrInvalidPassword = errors.New("auth: invalid password")
	ErrDisabled        = errors.New("auth: user disabled")
	ErrUsernameTaken   = errors.New("auth: username already in use")
	ErrTenantNotFound  = errors.New("auth: tenant not found")
	ErrSessionExpired  = errors.New("auth: session expired")
)

// Store wraps the sqlite/postgres CRUD for users, sessions, api_tokens, and
// the MFA factors (WebAuthn passkeys, TOTP, recovery codes). Engine selected
// at construction. mfaKey and wa are optional: absent them, TOTP and passkey
// enrollment respectively refuse with a clear error, but password auth and
// everything else keep working (so existing deployments upgrade cleanly).
type Store struct {
	db     *sql.DB
	engine Engine
	mfaKey []byte             // 32-byte AES-256-GCM key for TOTP secret encryption; nil disables TOTP
	wa     *webauthn.WebAuthn // relying-party handle; nil disables passkeys
}

// Engine selects parameter binding style. Mirrors journal.Engine.
type Engine int

const (
	EngineSQLite Engine = iota
	EnginePostgres
)

// Option configures a Store at construction.
type Option func(*Store)

// WithMFAKey enables TOTP by supplying the 32-byte AES-256-GCM key used to
// encrypt TOTP shared secrets at rest. Derive it from the daemon master key
// with DeriveMFAKey so it is cryptographically separated from the vault key.
func WithMFAKey(key []byte) Option { return func(s *Store) { s.mfaKey = key } }

// WithWebAuthn enables passkeys by supplying a configured relying-party handle
// (see NewWebAuthn).
func WithWebAuthn(wa *webauthn.WebAuthn) Option { return func(s *Store) { s.wa = wa } }

// New returns a Store bound to the given DB + engine, applying any options.
func New(db *sql.DB, engine Engine, opts ...Option) *Store {
	s := &Store{db: db, engine: engine}
	for _, o := range opts {
		o(s)
	}
	return s
}

// bind translates $N placeholders for sqlite (which uses ?).
func (s *Store) bind(q string) string {
	if s.engine == EnginePostgres {
		return q
	}
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		if q[i] != '$' {
			b.WriteByte(q[i])
			continue
		}
		i++
		for i < len(q) && q[i] >= '0' && q[i] <= '9' {
			i++
		}
		i--
		b.WriteByte('?')
	}
	return b.String()
}

// CreateUser inserts a user + returns the generated id. password is
// hashed with argon2id and the PHC string stored. Role is required;
// caller picks admin or member.
func (s *Store) CreateUser(ctx context.Context, username, password string, role Role) (string, error) {
	if username == "" {
		return "", errors.New("auth: username is required")
	}
	if len(password) < 8 {
		return "", errors.New("auth: password must be at least 8 characters")
	}
	if role != RoleAdmin && role != RoleMember {
		return "", fmt.Errorf("auth: unknown role %q", role)
	}
	id, err := newID("usr_")
	if err != nil {
		return "", err
	}
	phc, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	const q = `INSERT INTO users (id, username, password_phc, role) VALUES ($1, $2, $3, $4)`
	if _, err := s.db.ExecContext(ctx, s.bind(q), id, username, phc, string(role)); err != nil {
		if isUniqueErr(err) {
			return "", ErrUsernameTaken
		}
		return "", fmt.Errorf("auth: create user: %w", err)
	}
	return id, nil
}

// EnsureAdminWithPHC seeds an admin user whose password_phc is supplied
// directly (an argon2id PHC or a legacy lowercase hex sha256), inserting it
// only when no user with that username already exists. It bridges the legacy
// env-var BasicAuth (REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256,
// which carries a sha256 hash, never a plaintext password) into the users
// table so a basic-auth-only deployment gets a first-class, signed-in admin
// and can reach the session-gated dashboard write/build routes (upload,
// codegen, triggers). Returns true when a row was created. Idempotent: it is
// a no-op when the user already exists, so existing passwords + roles are
// never disturbed on restart.
func (s *Store) EnsureAdminWithPHC(ctx context.Context, username, phc string) (bool, error) {
	username = strings.TrimSpace(username)
	phc = strings.TrimSpace(phc)
	if username == "" || phc == "" {
		return false, errors.New("auth: username and password hash required")
	}
	// Already present: re-sync the password + admin role from the env so a
	// basic-auth deploy where the operator rotates REACTOR_BASIC_AUTH_* in the
	// env-file always has working creds (the env-file is the declared source of
	// truth for that deploy model; this mirrors setup's seedFirstAdmin). When
	// the row already matches, it's a true no-op.
	if existing, err := s.GetUserByUsername(ctx, username); err == nil {
		if existing.PasswordPHC == phc && existing.IsAdmin() {
			return false, nil
		}
		const upd = `UPDATE users SET password_phc = $1, role = $2 WHERE id = $3`
		if _, err := s.db.ExecContext(ctx, s.bind(upd), phc, string(RoleAdmin), existing.ID); err != nil {
			return false, fmt.Errorf("auth: resync admin: %w", err)
		}
		return false, nil
	}
	id, err := newID("usr_")
	if err != nil {
		return false, err
	}
	const q = `INSERT INTO users (id, username, password_phc, role) VALUES ($1, $2, $3, $4)`
	if _, err := s.db.ExecContext(ctx, s.bind(q), id, username, phc, string(RoleAdmin)); err != nil {
		if isUniqueErr(err) {
			return false, nil // raced with a concurrent seed; fine
		}
		return false, fmt.Errorf("auth: ensure admin: %w", err)
	}
	return true, nil
}

// GetUserByUsername returns the user for a login attempt.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	const q = `SELECT id, username, password_phc, role, tenant_id, disabled, created_at, updated_at, last_login_at
		FROM users WHERE username = $1`
	row := s.db.QueryRowContext(ctx, s.bind(q), username)
	return scanUser(row.Scan, s)
}

// GetUser returns the user by id.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	const q = `SELECT id, username, password_phc, role, tenant_id, disabled, created_at, updated_at, last_login_at
		FROM users WHERE id = $1`
	row := s.db.QueryRowContext(ctx, s.bind(q), id)
	return scanUser(row.Scan, s)
}

// ListUsers returns every user ordered by username. Used by the
// /users management page.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	const q = `SELECT id, username, password_phc, role, tenant_id, disabled, created_at, updated_at, last_login_at
		FROM users ORDER BY username ASC`
	rows, err := s.db.QueryContext(ctx, s.bind(q))
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows.Scan, s)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers is the cheap probe the BasicAuth fallback path uses to
// decide whether any user exists yet (zero users -> fall back to the
// env-var BasicAuth so the very first daemon boot still has a way in).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	const q = `SELECT COUNT(*) FROM users`
	var n int
	if err := s.db.QueryRowContext(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("auth: count users: %w", err)
	}
	return n, nil
}

// DeleteUser removes a user + their sessions and tokens via FK
// cascade. An admin cannot delete the last admin (would lock the
// daemon); the caller enforces.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	const q = `DELETE FROM users WHERE id = $1`
	res, err := s.db.ExecContext(ctx, s.bind(q), id)
	if err != nil {
		return fmt.Errorf("auth: delete user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserRole changes role. Caller enforces "cannot demote last admin".
func (s *Store) SetUserRole(ctx context.Context, id string, role Role) error {
	if role != RoleAdmin && role != RoleMember {
		return fmt.Errorf("auth: unknown role %q", role)
	}
	const q = `UPDATE users SET role = $1, updated_at = $2 WHERE id = $3`
	res, err := s.db.ExecContext(ctx, s.bind(q), string(role), nowUTC(), id)
	if err != nil {
		return fmt.Errorf("auth: set role: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserTenant moves a user to a tenant, which scopes their dashboard. An
// empty tenant falls back to 'default'.
func (s *Store) SetUserTenant(ctx context.Context, id, tenantID string) error {
	if tenantID == "" {
		tenantID = "default"
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT 1 FROM tenants WHERE tenant_id = $1`), tenantID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("auth: check tenant: %w", err)
	}
	const q = `UPDATE users SET tenant_id = $1, updated_at = $2 WHERE id = $3`
	res, err := s.db.ExecContext(ctx, s.bind(q), tenantID, nowUTC(), id)
	if err != nil {
		return fmt.Errorf("auth: set tenant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserDisabled flips the disabled flag. A disabled user cannot log
// in (Authenticate returns ErrDisabled); active sessions stay valid
// until expires_at or until manually revoked. Caller enforces "cannot
// disable last admin".
func (s *Store) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	const q = `UPDATE users SET disabled = $1, updated_at = $2 WHERE id = $3`
	res, err := s.db.ExecContext(ctx, s.bind(q), s.boolValue(disabled), nowUTC(), id)
	if err != nil {
		return fmt.Errorf("auth: set disabled: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountAdmins is used by the caller's "cannot demote/disable the last
// admin" guard.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	const q = `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = $1`
	var n int
	if err := s.db.QueryRowContext(ctx, s.bind(q), s.boolValue(false)).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// boolValue renders a Go bool the way each engine's driver expects it on
// a BOOLEAN column. modernc SQLite has no native bool and wants 1/0;
// pgx wants a real bool. Binding an int literal to a Postgres BOOLEAN
// column errors ("operator does not exist: boolean = integer"), which is
// why CountAdmins / SetUserDisabled / RevokeAPIToken all broke on
// Postgres before this.
func (s *Store) boolValue(b bool) any {
	if s.engine == EnginePostgres {
		return b
	}
	if b {
		return 1
	}
	return 0
}

// Authenticate looks up the user + verifies the password. Returns
// ErrInvalidPassword on mismatch, ErrDisabled when the row is set to
// disabled, ErrNotFound when the username does not exist.
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, error) {
	u, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		// Run a throwaway argon2 verification so a missing username
		// takes the same wall-clock time as a wrong password. Without
		// this, the fast no-such-user path is a username-enumeration
		// oracle.
		_ = VerifyPassword(dummyPHC, password)
		return User{}, err
	}
	// Always verify (even for disabled accounts) before branching so the
	// disabled-vs-enabled decision doesn't leak through timing either.
	ok := VerifyPassword(u.PasswordPHC, password)
	if u.Disabled {
		return User{}, ErrDisabled
	}
	if !ok {
		return User{}, ErrInvalidPassword
	}
	// Best-effort last_login_at bump.
	_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE users SET last_login_at = $1 WHERE id = $2`), nowUTC(), u.ID)
	return u, nil
}

// dummyPHC is a valid argon2id hash of a throwaway secret. Authenticate
// verifies against it on the no-such-user path so every failed login does
// the same amount of argon2 work, closing the timing side channel.
var dummyPHC = func() string {
	h, err := HashPassword("reactor-timing-equalizer-not-a-real-secret")
	if err != nil {
		// HashPassword only fails if crypto/rand fails, which is fatal
		// elsewhere too; fall back to a constant so Authenticate still
		// runs (the verify will simply mismatch, which is fine).
		return "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	return h
}()

// CreateSession mints a new session for the user + returns the raw
// cookie value. The DB row stores the sha256 hex hash. ttl is the
// session lifetime; the middleware checks expires_at on every request.
func (s *Store) CreateSession(ctx context.Context, userID, userAgent, ip string, ttl time.Duration) (string, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", fmt.Errorf("auth: session rand: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(rawBytes)
	hashHex := hashToken(raw)
	now := time.Now().UTC()
	expires := now.Add(ttl)
	const q = `INSERT INTO sessions (id_hash, user_id, expires_at, user_agent, ip) VALUES ($1, $2, $3, $4, $5)`
	if _, err := s.db.ExecContext(ctx, s.bind(q),
		hashHex, userID, formatTime(expires), userAgent, ip); err != nil {
		return "", fmt.Errorf("auth: create session: %w", err)
	}
	return raw, nil
}

// sessionIdleWindow invalidates a session that has gone unused for this long,
// independent of its absolute 7-day TTL. Bounds how long a leaked cookie is
// usable without activity.
const sessionIdleWindow = 3 * 24 * time.Hour

// ResolveSession looks up the session by cookie value. Returns
// ErrSessionExpired when the row exists but is past expires_at;
// ErrNotFound when no row matches; the User otherwise. Bumps
// last_seen_at on every successful resolve. Thin wrapper over
// ResolveSessionWithState for callers that don't need the MFA assurance level.
func (s *Store) ResolveSession(ctx context.Context, cookieValue string) (User, error) {
	u, _, err := s.ResolveSessionWithState(ctx, cookieValue)
	return u, err
}

// ResolveSessionWithState is ResolveSession plus the session's MFA assurance
// level (whether a second factor is still owed, and the step-up window). The
// auth middleware uses the state to gate an mfa_pending session down to just
// the MFA + logout routes, and dangerous handlers use it to require a fresh
// step-up. Enforces the absolute TTL, the idle window, and disabled-user
// invalidation exactly as before.
func (s *Store) ResolveSessionWithState(ctx context.Context, cookieValue string) (User, SessionState, error) {
	hashHex := hashToken(cookieValue)
	const q = `SELECT s.expires_at, s.last_seen_at, s.mfa_pending, s.elevated_until, u.id, u.username, u.password_phc, u.role, u.tenant_id, u.disabled, u.created_at, u.updated_at, u.last_login_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id_hash = $1`
	row := s.db.QueryRowContext(ctx, s.bind(q), hashHex)
	var (
		expiresStr string
		lastSeen   sql.NullString
		mfaPending any
		elevated   sql.NullString
		u          User
		passPHC    string
		role       string
		disabled   any
		created    sql.NullString
		updated    sql.NullString
		lastLogin  sql.NullString
	)
	if err := row.Scan(&expiresStr, &lastSeen, &mfaPending, &elevated, &u.ID, &u.Username, &passPHC, &role, &u.TenantID, &disabled, &created, &updated, &lastLogin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, SessionState{}, ErrNotFound
		}
		return User{}, SessionState{}, fmt.Errorf("auth: resolve session: %w", err)
	}
	expires, err := parseTime(expiresStr)
	if err != nil {
		return User{}, SessionState{}, fmt.Errorf("auth: parse session expiry: %w", err)
	}
	if time.Now().UTC().After(expires) {
		// Best-effort sweep of the expired row.
		_, _ = s.db.ExecContext(ctx, s.bind(`DELETE FROM sessions WHERE id_hash = $1`), hashHex)
		return User{}, SessionState{}, ErrSessionExpired
	}
	// Idle timeout: a session unused for longer than the idle window is
	// invalidated even though its absolute 7-day TTL has not elapsed, bounding
	// how long a stolen/leaked cookie stays usable without activity.
	if lastSeen.Valid {
		if seen, perr := parseTime(lastSeen.String); perr == nil && time.Now().UTC().Sub(seen) > sessionIdleWindow {
			_, _ = s.db.ExecContext(ctx, s.bind(`DELETE FROM sessions WHERE id_hash = $1`), hashHex)
			return User{}, SessionState{}, ErrSessionExpired
		}
	}
	u.PasswordPHC = passPHC
	u.Role = Role(role)
	u.Disabled = parseBool(disabled)
	if u.Disabled {
		// A disabled user's session is no longer valid.
		_, _ = s.db.ExecContext(ctx, s.bind(`DELETE FROM sessions WHERE user_id = $1`), u.ID)
		return User{}, SessionState{}, ErrDisabled
	}
	if created.Valid {
		if t, err := parseTime(created.String); err == nil {
			u.CreatedAt = t
		}
	}
	if updated.Valid {
		if t, err := parseTime(updated.String); err == nil {
			u.UpdatedAt = t
		}
	}
	if lastLogin.Valid {
		if t, err := parseTime(lastLogin.String); err == nil {
			u.LastLoginAt = &t
		}
	}
	st := SessionState{IDHash: hashHex, MFAPending: parseBool(mfaPending)}
	if elevated.Valid {
		if t, perr := parseTime(elevated.String); perr == nil {
			st.ElevatedUntil = t
		}
	}
	// Best-effort bump of last_seen_at; failures don't block the request.
	_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE sessions SET last_seen_at = $1 WHERE id_hash = $2`), nowUTC(), hashHex)
	return u, st, nil
}

// DestroySession removes the row for the given cookie value. Used by
// /logout. No error when the cookie does not resolve (treat as a
// successful logout from the operator's perspective).
func (s *Store) DestroySession(ctx context.Context, cookieValue string) error {
	hashHex := hashToken(cookieValue)
	const q = `DELETE FROM sessions WHERE id_hash = $1`
	_, err := s.db.ExecContext(ctx, s.bind(q), hashHex)
	return err
}

// DestroyAllSessionsForUser revokes every session for a user. Used
// when an admin forces a password reset or disables an account.
func (s *Store) DestroyAllSessionsForUser(ctx context.Context, userID string) error {
	const q = `DELETE FROM sessions WHERE user_id = $1`
	_, err := s.db.ExecContext(ctx, s.bind(q), userID)
	return err
}

// SweepExpiredSessions drops expired rows. Called periodically by the
// daemon.
func (s *Store) SweepExpiredSessions(ctx context.Context) (int64, error) {
	const q = `DELETE FROM sessions WHERE expires_at < $1`
	res, err := s.db.ExecContext(ctx, s.bind(q), nowUTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// MintAPIToken returns the raw token (to show the user once) + the
// stored row's id. token_hash holds sha256(raw) for lookups; the
// caller never re-reads the raw value.
func (s *Store) MintAPIToken(ctx context.Context, userID, name string, ttl time.Duration) (rawToken, tokenID string, err error) {
	if name == "" {
		return "", "", errors.New("auth: token name is required")
	}
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", "", err
	}
	raw := "rtr_" + base64.RawURLEncoding.EncodeToString(rawBytes)
	hashHex := hashToken(raw)
	id, err := newID("tok_")
	if err != nil {
		return "", "", err
	}
	var expires *string
	if ttl > 0 {
		s := formatTime(time.Now().UTC().Add(ttl))
		expires = &s
	}
	const q = `INSERT INTO api_tokens (id, user_id, name, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5)`
	if _, err := s.db.ExecContext(ctx, s.bind(q), id, userID, name, hashHex, expires); err != nil {
		return "", "", fmt.Errorf("auth: mint token: %w", err)
	}
	return raw, id, nil
}

// ResolveAPIToken looks up the user for an API token. Returns
// ErrNotFound when the token does not resolve; ErrSessionExpired
// when revoked or past expires_at.
func (s *Store) ResolveAPIToken(ctx context.Context, raw string) (User, error) {
	hashHex := hashToken(raw)
	const q = `SELECT t.id, t.expires_at, t.revoked, u.id, u.username, u.role, u.tenant_id, u.disabled
		FROM api_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1`
	row := s.db.QueryRowContext(ctx, s.bind(q), hashHex)
	var (
		tokenID    string
		expiresRaw sql.NullString
		revoked    any
		u          User
		role       string
		disabled   any
	)
	if err := row.Scan(&tokenID, &expiresRaw, &revoked, &u.ID, &u.Username, &role, &u.TenantID, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("auth: resolve token: %w", err)
	}
	if parseBool(revoked) {
		return User{}, ErrSessionExpired
	}
	if expiresRaw.Valid {
		t, perr := parseTime(expiresRaw.String)
		if perr != nil {
			// Corrupt auth metadata must never silently become a bearer
			// token with no deadline. Fail closed and require a replacement.
			return User{}, ErrSessionExpired
		}
		if time.Now().UTC().After(t) {
			return User{}, ErrSessionExpired
		}
	}
	u.Role = Role(role)
	u.Disabled = parseBool(disabled)
	if u.Disabled {
		return User{}, ErrDisabled
	}
	// Best-effort last-used bump.
	_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE api_tokens SET last_used_at = $1 WHERE id = $2`), nowUTC(), tokenID)
	return u, nil
}

// ListAPITokens lists tokens for one user (drives the dashboard page).
// raw token values never leave the daemon after mint.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	const q = `SELECT id, user_id, name, token_hash, created_at, last_used_at, expires_at, revoked
		FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, s.bind(q), userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list tokens: %w", err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var (
			t           APIToken
			lastUsed    sql.NullString
			expires     sql.NullString
			created     sql.NullString
			revokedScan any
		)
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &created, &lastUsed, &expires, &revokedScan); err != nil {
			return nil, err
		}
		if created.Valid {
			if ts, perr := parseTime(created.String); perr == nil {
				t.CreatedAt = ts
			}
		}
		if lastUsed.Valid {
			if ts, perr := parseTime(lastUsed.String); perr == nil {
				t.LastUsedAt = &ts
			}
		}
		if expires.Valid {
			if ts, perr := parseTime(expires.String); perr == nil {
				t.ExpiresAt = &ts
			}
		}
		t.Revoked = parseBool(revokedScan)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken sets revoked=true. The row stays so the audit trail
// of "this token did X" survives revocation.
func (s *Store) RevokeAPIToken(ctx context.Context, id, userID string) error {
	const q = `UPDATE api_tokens SET revoked = $1 WHERE id = $2 AND user_id = $3`
	res, err := s.db.ExecContext(ctx, s.bind(q), s.boolValue(true), id, userID)
	if err != nil {
		return fmt.Errorf("auth: revoke token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// HashPassword hashes a password with argon2id and returns the PHC
// string the password_phc column stores. Uses OWASP-recommended
// defaults (64 MiB, t=3, p=2, 16-byte salt, 32-byte hash).
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const (
		m uint32 = 64 * 1024
		t uint32 = 3
		p uint8  = 2
	)
	hash := argon2.IDKey([]byte(password), salt, t, m, p, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		m, t, p,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword constant-time-compares the password against the
// stored PHC. Sniffs the prefix and routes to argon2id or legacy hex
// SHA-256 so an operator can paste their env-var-configured BasicAuth
// hash as the first admin without re-hashing. Returns false on any
// parse error.
func VerifyPassword(stored, plaintext string) bool {
	stored = strings.TrimSpace(stored)
	if strings.HasPrefix(stored, "$argon2id$") {
		params, salt, hash, err := parseArgon2idPHC(stored)
		if err != nil {
			return false
		}
		// Cost floor. The verifier recomputes with whatever m/t/p the stored
		// PHC carries, so an ancient or tampered weak hash would silently
		// downgrade the KDF to something GPU-crackable. Fail closed and make
		// the operator re-hash; the default is far above this.
		if params.m < MinArgon2MemKiB || params.t < MinArgon2Time {
			return false
		}
		got := argon2.IDKey([]byte(plaintext), salt, params.t, params.m, params.p, uint32(len(hash)))
		return constTimeEqualBytes(got, hash)
	}
	// Legacy hex sha256 fallback.
	gotHex := sha256HexLower(plaintext)
	return constTimeEqualBytes([]byte(strings.ToLower(stored)), []byte(gotHex))
}

func sha256HexLower(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func constTimeEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// OWASP-minimum argon2id cost this package will accept at verify time. Below
// this a stored PHC is treated as invalid (fail closed) rather than silently
// downgrading the KDF. Exported so the HTTP layer shares one floor instead of
// keeping a second copy that can drift.
const (
	MinArgon2MemKiB uint32 = 19456 // 19 MiB
	MinArgon2Time   uint32 = 2
)

type argon2idParams struct {
	m uint32
	t uint32
	p uint8
}

func parseArgon2idPHC(s string) (argon2idParams, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return argon2idParams{}, nil, nil, errors.New("auth: bad PHC")
	}
	var p argon2idParams
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return argon2idParams{}, nil, nil, fmt.Errorf("auth: bad param %q", kv)
		}
		// strconv, not fmt.Sscanf: Sscanf accepts a leading-numeric prefix and
		// reports no error on trailing garbage.
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return argon2idParams{}, nil, nil, fmt.Errorf("auth: parse param %q: %w", kv, err)
		}
		switch k {
		case "m":
			p.m = uint32(n)
		case "t":
			p.t = uint32(n)
		case "p":
			if n == 0 || n > 255 {
				return argon2idParams{}, nil, nil, errors.New("auth: p out of range")
			}
			p.p = uint8(n)
		default:
			return argon2idParams{}, nil, nil, fmt.Errorf("auth: unknown param %q", k)
		}
	}
	// argon2.IDKey PANICS when time < 1 or threads < 1, so these are an
	// availability guard as much as a correctness one: a typo in the operator's
	// env hash would otherwise take down every login attempt.
	if p.m == 0 || p.t == 0 || p.p == 0 {
		return argon2idParams{}, nil, nil, errors.New("auth: missing required parameter")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2idParams{}, nil, nil, err
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2idParams{}, nil, nil, err
	}
	return p, salt, hash, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func newID(prefix string) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buf), nil
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func nowUTC() string {
	return formatTime(time.Now().UTC())
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("auth: cannot parse time %q", s)
}

func parseBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case []byte:
		s := strings.ToLower(string(x))
		return s == "1" || s == "true" || s == "t"
	case string:
		s := strings.ToLower(x)
		return s == "1" || s == "true" || s == "t"
	}
	return false
}

// scanUser materialises a User from a row scan.
func scanUser(scan func(...any) error, _ *Store) (User, error) {
	var (
		u         User
		role      string
		disabled  any
		created   sql.NullString
		updated   sql.NullString
		lastLogin sql.NullString
	)
	if err := scan(&u.ID, &u.Username, &u.PasswordPHC, &role, &u.TenantID, &disabled, &created, &updated, &lastLogin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	u.Role = Role(role)
	u.Disabled = parseBool(disabled)
	if created.Valid {
		if t, err := parseTime(created.String); err == nil {
			u.CreatedAt = t
		}
	}
	if updated.Valid {
		if t, err := parseTime(updated.String); err == nil {
			u.UpdatedAt = t
		}
	}
	if lastLogin.Valid {
		if t, err := parseTime(lastLogin.String); err == nil {
			u.LastLoginAt = &t
		}
	}
	return u, nil
}

// isUniqueErr probes a DB error for "UNIQUE constraint failed".
// sqlite formats it one way, postgres another; we sniff both.
func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

// EncodeArgon2idPHCForTest builds a PHC string at explicit costs. Exported for
// tests that need a hash BELOW the production floor, which HashPassword will
// never produce.
func EncodeArgon2idPHCForTest(password string, salt []byte, m, t uint32, p uint8) string {
	hash := argon2.IDKey([]byte(password), salt, t, m, p, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		m, t, p,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// ErrPasswordTooShort is returned when a new password is under the minimum.
var ErrPasswordTooShort = errors.New("auth: password must be at least 8 characters")

// SetPassword replaces a user's password and invalidates every session they
// hold. Used by the admin reset path; ChangePassword wraps it with a
// current-password check for the self-service path.
//
// Destroying sessions is the point of the operation as much as the new hash is:
// a password is usually reset BECAUSE the old one may be known to someone else,
// and leaving live cookies valid would keep that access open. API tokens are a
// separate credential class and are deliberately left alone; revoke them
// explicitly from the tokens page.
func (s *Store) SetPassword(ctx context.Context, userID, newPassword string) error {
	if userID == "" {
		return errors.New("auth: user id is required")
	}
	if len(newPassword) < 8 {
		return ErrPasswordTooShort
	}
	phc, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	const q = `UPDATE users SET password_phc = $1, updated_at = $2 WHERE id = $3`
	res, err := s.db.ExecContext(ctx, s.bind(q), phc, nowUTC(), userID)
	if err != nil {
		return fmt.Errorf("auth: set password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := s.DestroyAllSessionsForUser(ctx, userID); err != nil {
		return fmt.Errorf("auth: set password: revoke sessions: %w", err)
	}
	return nil
}

// ChangePassword is the self-service path: it verifies the CURRENT password
// before setting the new one, so a stolen session cookie alone cannot take
// over the account by rotating its password.
func (s *Store) ChangePassword(ctx context.Context, userID, current, next string) error {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if !VerifyPassword(u.PasswordPHC, current) {
		return ErrInvalidPassword
	}
	return s.SetPassword(ctx, userID, next)
}
