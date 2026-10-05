package server

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

var totpOpts = totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// newMFAServer builds a test server with a TOTP-capable auth store and an admin
// user "alice" who has a CONFIRMED TOTP factor. Returns the server URL, store,
// the user id, and the TOTP secret (so the test can mint valid codes).
func newMFAServer(t *testing.T) (string, *auth.Store, string, string, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "s.db")
	dbURL := "sqlite://" + dbPath
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, dbURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := auth.New(db, auth.EngineSQLite, auth.WithMFAKey(auth.DeriveMFAKey([]byte("test-master-key-0123456789abcdef"))))
	uid, err := store.CreateUser(ctx, "alice", "secret-pass", auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := store.GetUser(ctx, uid)
	secret, _, err := store.BeginTOTPEnrollment(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	// Confirm with the previous step's code so the current step is free.
	confirm, _ := totp.GenerateCodeCustom(secret, time.Now().Add(-30*time.Second), totpOpts)
	if err := store.ConfirmTOTP(ctx, uid, confirm); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}

	s := &Server{
		Journal:     journal.New(db, journal.EngineSQLite),
		Credentials: credentials.New(db, credentials.EngineSQLite),
		Registry:    registry.New(filepath.Join(dir, "workflows")),
		Auth:        store,
		Log:         silent,
		Version:     "test",
	}
	r := chi.NewRouter()
	s.Mount(r)
	srv := httptest.NewServer(r)
	return srv.URL, store, uid, secret, func() { srv.Close(); db.Close() }
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

func formPost(t *testing.T, cl *http.Client, base, path string, cookie *http.Cookie, form url.Values) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getWith(t *testing.T, cl *http.Client, base, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	req.Header.Set("Accept", "text/html")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestMFALoginFlowGatesPendingSession(t *testing.T) {
	base, _, _, secret, cleanup := newMFAServer(t)
	defer cleanup()
	cl := noRedirectClient()

	// 1. Password login -> pending session, redirected to the MFA challenge.
	resp := formPost(t, cl, base, "/login", nil, url.Values{
		"username": {"alice"}, "password": {"secret-pass"}, "next": {"/runs"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login/mfa") {
		t.Fatalf("login redirect = %q, want /login/mfa", loc)
	}
	cookie := sessionCookie(resp)
	if cookie == nil {
		t.Fatal("no session cookie on pending login")
	}

	// 2. The pending session is gated: any app route bounces to the challenge.
	resp = getWith(t, cl, base, "/runs", cookie)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login/mfa") {
		t.Fatalf("pending /runs status=%d loc=%q, want 303 -> /login/mfa", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 3. The challenge page itself is reachable.
	resp = getWith(t, cl, base, "/login/mfa?next=/runs", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge page status = %d", resp.StatusCode)
	}

	// 4. A wrong TOTP code does not clear the gate.
	resp = formPost(t, cl, base, "/login/mfa/totp", cookie, url.Values{"code": {"000000"}, "next": {"/runs"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d, want 401", resp.StatusCode)
	}

	// 5. A valid TOTP code clears the second factor.
	code, _ := totp.GenerateCodeCustom(secret, time.Now(), totpOpts)
	resp = formPost(t, cl, base, "/login/mfa/totp", cookie, url.Values{"code": {code}, "next": {"/runs"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/runs" {
		t.Fatalf("valid code status=%d loc=%q, want 303 -> /runs", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 6. The now-full session reaches app routes (no longer gated).
	resp = getWith(t, cl, base, "/runs", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-mfa /runs status = %d, want 200", resp.StatusCode)
	}
}

// TestBasicAuthRefusedForMFAUser guards the critical fix: HTTP Basic (single
// factor) must not satisfy a request for a user who owes a second factor, while
// a user without MFA can still use Basic.
func TestBasicAuthRefusedForMFAUser(t *testing.T) {
	base, store, _, _, cleanup := newMFAServer(t)
	defer cleanup()
	cl := noRedirectClient()

	// alice has a confirmed TOTP factor -> Basic must be refused.
	req, _ := http.NewRequest(http.MethodGet, base+"/runs", nil)
	req.SetBasicAuth("alice", "secret-pass")
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Basic for MFA-enrolled user status = %d, want 401", resp.StatusCode)
	}

	// A user WITHOUT a factor can still authenticate via Basic.
	if _, err := store.CreateUser(context.Background(), "bob", "secret-pass", auth.RoleMember); err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodGet, base+"/runs", nil)
	req2.SetBasicAuth("bob", "secret-pass")
	req2.Header.Set("Accept", "text/html")
	resp2, err := cl.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Basic for non-MFA user status = %d, want 200", resp2.StatusCode)
	}
}

func TestSecurityMutationRequiresStepUp(t *testing.T) {
	base, store, uid, secret, cleanup := newMFAServer(t)
	defer cleanup()
	cl := noRedirectClient()
	ctx := context.Background()

	// A full, non-elevated session (as if MFA was already cleared at login).
	raw, err := store.CreateSession(ctx, uid, "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: SessionCookieName, Value: raw}

	// /security renders and prompts for verification (user has a factor).
	resp := getWith(t, cl, base, "/security", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/security status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Verify your identity") {
		t.Fatal("/security did not show the step-up prompt for a non-elevated session")
	}

	// A mutation is refused without a fresh step-up.
	resp = formPost(t, cl, base, "/security/totp/disable", cookie, url.Values{})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disable-without-stepup status = %d, want 403", resp.StatusCode)
	}

	// Step up with a valid TOTP code -> session elevated.
	code, _ := totp.GenerateCodeCustom(secret, time.Now(), totpOpts)
	resp = formPost(t, cl, base, "/security/stepup/totp", cookie, url.Values{"code": {code}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("stepup status = %d, want 303", resp.StatusCode)
	}

	// The same mutation now succeeds.
	resp = formPost(t, cl, base, "/security/totp/disable", cookie, url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("disable-after-stepup status = %d, want 303", resp.StatusCode)
	}
	if ok, _ := store.HasConfirmedTOTP(ctx, uid); ok {
		t.Fatal("TOTP still enabled after authorized disable")
	}
}

func TestTokenMintWithBrowserSessionStillRequiresMFAStepUp(t *testing.T) {
	base, store, userID, secret, cleanup := newMFAServer(t)
	defer cleanup()
	client := noRedirectClient()
	ctx := context.Background()

	rawSession, err := store.CreateSession(ctx, userID, "test", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: SessionCookieName, Value: rawSession}
	form := url.Values{"name": {"browser-mfa"}, "ttl_days": {"1"}}
	resp := formPost(t, client, base, "/tokens", cookie, form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mint before step-up status = %d, want 403", resp.StatusCode)
	}
	tokens, err := store.ListAPITokens(ctx, userID)
	if err != nil || len(tokens) != 0 {
		t.Fatalf("tokens before step-up = %d, err = %v; want 0", len(tokens), err)
	}

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpOpts)
	if err != nil {
		t.Fatal(err)
	}
	resp = formPost(t, client, base, "/security/stepup/totp", cookie, url.Values{"code": {code}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("step-up status = %d, want 303", resp.StatusCode)
	}
	resp = formPost(t, client, base, "/tokens", cookie, form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/tokens" {
		t.Fatalf("mint after step-up status = %d, location = %q; want 303 /tokens", resp.StatusCode, resp.Header.Get("Location"))
	}
	tokens, err = store.ListAPITokens(ctx, userID)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens after step-up = %d, err = %v; want 1", len(tokens), err)
	}
}
