package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "a.db")
	url := "sqlite://" + dbPath
	silent := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return New(db, EngineSQLite), func() { db.Close() }
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func TestCreateUserAndAuthenticate(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()

	id, err := s.CreateUser(ctx, "alice", "secret-pass", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "usr_") {
		t.Fatalf("id = %q", id)
	}

	u, err := s.Authenticate(ctx, "alice", "secret-pass")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if u.ID != id || !u.IsAdmin() {
		t.Fatalf("got %+v", u)
	}

	if _, err := s.Authenticate(ctx, "alice", "wrong"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("wrong pw err = %v", err)
	}
	if _, err := s.Authenticate(ctx, "nobody", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}
}

func TestCreateUserRejectsShortPassword(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	if _, err := s.CreateUser(context.Background(), "alice", "short", RoleMember); err == nil {
		t.Fatal("short password should have been rejected")
	}
}

func TestUsernameUnique(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "alice", "secret-pass", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateUser(ctx, "alice", "secret-pass", RoleAdmin)
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, "alice", "secret-pass", RoleAdmin)

	cookie, err := s.CreateSession(ctx, id, "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cookie == "" {
		t.Fatal("empty cookie")
	}

	u, err := s.ResolveSession(ctx, cookie)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if u.ID != id {
		t.Fatalf("got user %s", u.ID)
	}

	// Bogus cookie -> not found.
	if _, err := s.ResolveSession(ctx, "not-a-cookie"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bogus err = %v", err)
	}

	// Destroy + re-resolve -> not found.
	if err := s.DestroySession(ctx, cookie); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSession(ctx, cookie); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-destroy err = %v", err)
	}
}

func TestSessionExpiresSweep(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, "alice", "secret-pass", RoleAdmin)
	cookie, _ := s.CreateSession(ctx, id, "", "", -time.Minute) // already expired
	if _, err := s.ResolveSession(ctx, cookie); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
}

func TestDisabledUserCannotAuthenticate(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	id, _ := s.CreateUser(ctx, "alice", "secret-pass", RoleMember)
	if err := s.SetUserDisabled(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "alice", "secret-pass"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
}

func TestSetUserRoleAndCountAdmins(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	a, _ := s.CreateUser(ctx, "alice", "secret-pass", RoleAdmin)
	_, _ = s.CreateUser(ctx, "bob", "secret-pass", RoleMember)

	n, _ := s.CountAdmins(ctx)
	if n != 1 {
		t.Fatalf("admin count = %d, want 1", n)
	}
	if err := s.SetUserRole(ctx, a, RoleMember); err != nil {
		t.Fatal(err)
	}
	n, _ = s.CountAdmins(ctx)
	if n != 0 {
		t.Fatalf("admin count after demote = %d, want 0", n)
	}
}

func TestSetUserTenantRequiresRegisteredTenant(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	id, err := s.CreateUser(ctx, "tenant-user", "secret-pass", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserTenant(ctx, id, "missing"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("missing tenant err = %v, want ErrTenantNotFound", err)
	}
	u, err := s.GetUser(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if u.TenantID != "default" {
		t.Fatalf("tenant after rejected assignment = %q, want default", u.TenantID)
	}
	if _, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO tenants (tenant_id, name, plan) VALUES ($1, $2, $3)`), "acme", "Acme", "custom"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserTenant(ctx, id, "acme"); err != nil {
		t.Fatalf("registered tenant assignment: %v", err)
	}
	u, err = s.GetUser(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if u.TenantID != "acme" {
		t.Fatalf("tenant after assignment = %q, want acme", u.TenantID)
	}
}

func TestAPITokenMintListResolveRevoke(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	uid, _ := s.CreateUser(ctx, "alice", "secret-pass", RoleAdmin)

	raw, tid, err := s.MintAPIToken(ctx, uid, "ci-deploy", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "rtr_") {
		t.Fatalf("raw token = %q", raw)
	}

	u, err := s.ResolveAPIToken(ctx, raw)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if u.ID != uid {
		t.Fatalf("user mismatch: %s", u.ID)
	}

	list, _ := s.ListAPITokens(ctx, uid)
	if len(list) != 1 || list[0].ID != tid {
		t.Fatalf("list = %+v", list)
	}

	if err := s.RevokeAPIToken(ctx, tid, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAPIToken(ctx, raw); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("post-revoke err = %v", err)
	}
}

func TestAPITokenMalformedExpiryFailsClosed(t *testing.T) {
	t.Parallel()
	s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	uid, _ := s.CreateUser(ctx, "expiry-user", "secret-pass", RoleAdmin)
	raw, _, err := s.MintAPIToken(ctx, uid, "broken-expiry", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE api_tokens SET expires_at = $1 WHERE name = $2`), "not-a-timestamp", "broken-expiry"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAPIToken(ctx, raw); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("malformed expiry error = %v, want ErrSessionExpired", err)
	}
}

func TestVerifyPasswordAcceptsLegacyHexSha256(t *testing.T) {
	t.Parallel()
	// "secret-pass" -> hex sha256.
	stored := sha256HexLower("secret-pass")
	if !VerifyPassword(stored, "secret-pass") {
		t.Fatal("legacy hex sha256 path failed")
	}
	if VerifyPassword(stored, "wrong") {
		t.Fatal("legacy path matched wrong password")
	}
}

func TestVerifyPasswordArgon2idRoundTrip(t *testing.T) {
	t.Parallel()
	phc, err := HashPassword("secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$") {
		t.Fatalf("phc = %q", phc)
	}
	if !VerifyPassword(phc, "secret-pass") {
		t.Fatal("argon2id verify failed")
	}
	if VerifyPassword(phc, "nope") {
		t.Fatal("argon2id accepted wrong password")
	}
}

// TestEnsureAdminWithPHC covers the env-BasicAuth -> users-table bridge:
// a basic-auth-only deploy must get a first-class signed-in admin (so the
// session-gated write/build routes are reachable), seeded directly from the
// sha256 hash the env carries, and re-synced when the env password rotates.
func TestEnsureAdminWithPHC(t *testing.T) {
	s, done := newTestStore(t)
	defer done()
	ctx := context.Background()
	phcOf := func(pw string) string { sum := sha256.Sum256([]byte(pw)); return hex.EncodeToString(sum[:]) }

	pw := "operator-secret-1"
	created, err := s.EnsureAdminWithPHC(ctx, "admin", phcOf(pw))
	if err != nil || !created {
		t.Fatalf("first seed: created=%v err=%v", created, err)
	}
	u, err := s.Authenticate(ctx, "admin", pw)
	if err != nil {
		t.Fatalf("authenticate after seed: %v", err)
	}
	if !u.IsAdmin() {
		t.Fatalf("seeded user role = %q, want admin", u.Role)
	}

	// Idempotent: same hash is a no-op (not re-created), still authenticates.
	created, err = s.EnsureAdminWithPHC(ctx, "admin", phcOf(pw))
	if err != nil || created {
		t.Fatalf("re-seed same: created=%v err=%v", created, err)
	}
	if _, err := s.Authenticate(ctx, "admin", pw); err != nil {
		t.Fatalf("authenticate after no-op re-seed: %v", err)
	}

	// Rotated env password: re-syncs so the NEW creds work and the OLD fail.
	pw2 := "operator-secret-2"
	if _, err := s.EnsureAdminWithPHC(ctx, "admin", phcOf(pw2)); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if _, err := s.Authenticate(ctx, "admin", pw2); err != nil {
		t.Fatalf("authenticate after rotate: %v", err)
	}
	if _, err := s.Authenticate(ctx, "admin", pw); err == nil {
		t.Fatal("old password still authenticates after env rotation")
	}

	// Blank inputs are rejected.
	if _, err := s.EnsureAdminWithPHC(ctx, "", "x"); err == nil {
		t.Fatal("empty username accepted")
	}
}
