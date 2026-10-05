package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/auth"
)

type sharedFlashBackend struct {
	mu   sync.Mutex
	rows map[string]flashEntry
}

func newSharedFlashBackend() *sharedFlashBackend {
	return &sharedFlashBackend{rows: make(map[string]flashEntry)}
}

func (b *sharedFlashBackend) PutOneTimeFlash(_ context.Context, key string, ciphertext []byte, expires time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rows[key] = flashEntry{ciphertext: append([]byte(nil), ciphertext...), expires: expires}
	return nil
}

func (b *sharedFlashBackend) TakeOneTimeFlash(_ context.Context, key string) ([]byte, time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.rows[key]
	delete(b.rows, key)
	if !ok {
		return nil, time.Time{}, errors.New("missing")
	}
	return append([]byte(nil), entry.ciphertext...), entry.expires, nil
}

func (b *sharedFlashBackend) PurgeExpiredOneTimeFlashes(_ context.Context, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, entry := range b.rows {
		if !entry.expires.After(now) {
			delete(b.rows, key)
		}
	}
	return nil
}

func TestFlashRoundTripDeletesAfterTake(t *testing.T) {
	t.Parallel()
	s := newFlashStore()

	// put writes a cookie + stashes the payload.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := s.put(w1, r1, map[string]string{"k": "v"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	resp1 := w1.Result()
	cookies := resp1.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count = %d, want 1", len(cookies))
	}
	c := cookies[0]
	if c.HttpOnly != true || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("flash cookie missing security attrs: %+v", c)
	}

	// take with the cookie returns the payload + clears the cookie.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/dest", nil)
	r2.AddCookie(c)
	got := s.take(w2, r2)
	if got["k"] != "v" {
		t.Fatalf("take payload = %+v, want {k:v}", got)
	}
	resp2 := w2.Result()
	if got := resp2.Header.Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Fatalf("flash reveal Cache-Control = %q, want no-store", got)
	}
	clearCookies := resp2.Cookies()
	if len(clearCookies) != 1 || clearCookies[0].MaxAge != -1 {
		t.Fatalf("take must clear flash cookie via MaxAge=-1; got %+v", clearCookies)
	}

	// Second take returns nothing (single-use).
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/dest", nil)
	r3.AddCookie(c)
	if again := s.take(w3, r3); again != nil {
		t.Fatalf("second take = %+v, want nil (single-use)", again)
	}
}

func TestFlashRoundTripAcrossReplicasStoresOnlyCiphertext(t *testing.T) {
	t.Parallel()
	backend := newSharedFlashBackend()
	producer := newFlashStore(backend)
	consumer := newFlashStore(backend)
	producer.secureCookies = true
	consumer.secureCookies = true

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "http://internal/create", nil)
	secret := "one-time-raw-secret"
	if err := producer.put(w1, r1, map[string]string{"secret": secret}); err != nil {
		t.Fatal(err)
	}
	cookie := w1.Result().Cookies()[0]
	if !cookie.Secure {
		t.Fatal("SecureCookies did not mark the flash capability Secure behind TLS termination")
	}

	backend.mu.Lock()
	if len(backend.rows) != 1 {
		backend.mu.Unlock()
		t.Fatalf("shared rows = %d, want 1", len(backend.rows))
	}
	for key, entry := range backend.rows {
		if key == cookie.Value || bytes.Contains(entry.ciphertext, []byte(secret)) {
			backend.mu.Unlock()
			t.Fatal("shared flash storage contains the raw capability or plaintext secret")
		}
	}
	backend.mu.Unlock()

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "http://other-replica/dest", nil)
	r2.AddCookie(cookie)
	if got := consumer.take(w2, r2); got["secret"] != secret {
		t.Fatalf("cross-replica payload = %+v", got)
	}

	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/dest", nil)
	r3.AddCookie(cookie)
	if got := producer.take(w3, r3); got != nil {
		t.Fatalf("replayed cross-replica flash = %+v, want nil", got)
	}
}

func TestFlashTamperedCapabilityCannotDecryptOrReplay(t *testing.T) {
	t.Parallel()
	backend := newSharedFlashBackend()
	store := newFlashStore(backend)
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := store.put(w1, r1, map[string]string{"secret": "value"}); err != nil {
		t.Fatal(err)
	}
	original := w1.Result().Cookies()[0]
	tampered := *original
	tampered.Value = "0" + tampered.Value[1:]
	if tampered.Value == original.Value {
		tampered.Value = "1" + tampered.Value[1:]
	}

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&tampered)
	if got := store.take(w2, r2); got != nil {
		t.Fatalf("tampered capability returned %+v", got)
	}

	// A forged lookup cannot consume the real digest; the original capability
	// remains usable once and only once.
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.AddCookie(original)
	if got := store.take(w3, r3); got["secret"] != "value" {
		t.Fatalf("original capability after forgery = %+v", got)
	}
}

func TestFlashTakeWithoutCookieReturnsNil(t *testing.T) {
	t.Parallel()
	s := newFlashStore()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := s.take(w, r); got != nil {
		t.Fatalf("take without cookie = %+v, want nil", got)
	}
}

func TestFlashExpiredEntryReturnsNil(t *testing.T) {
	t.Parallel()
	s := newFlashStore()
	s.ttl = -time.Second // entries are dead-on-arrival
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := s.put(w1, r1, map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	c := w1.Result().Cookies()[0]

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(c)
	if got := s.take(w2, r2); got != nil {
		t.Fatalf("expired take = %+v, want nil", got)
	}
}

type failingFlashBackend struct{}

func (failingFlashBackend) PutOneTimeFlash(context.Context, string, []byte, time.Time) error {
	return errors.New("flash backend unavailable")
}
func (failingFlashBackend) TakeOneTimeFlash(context.Context, string) ([]byte, time.Time, error) {
	return nil, time.Time{}, errors.New("missing")
}
func (failingFlashBackend) PurgeExpiredOneTimeFlashes(context.Context, time.Time) error { return nil }

type tokenRollbackAuth struct {
	AuthAdmin
	revokedTokenID string
	revokedUserID  string
}

func (*tokenRollbackAuth) HasMFA(context.Context, string) (bool, error) { return false, nil }

func (*tokenRollbackAuth) MintAPIToken(context.Context, string, string, time.Duration) (string, string, error) {
	return "rtr_raw_one_time_token", "tok_new", nil
}

func (a *tokenRollbackAuth) RevokeAPIToken(_ context.Context, tokenID, userID string) error {
	a.revokedTokenID = tokenID
	a.revokedUserID = userID
	return nil
}

func TestTokenCreateRevokesCredentialWhenOneTimeDeliveryFails(t *testing.T) {
	t.Parallel()
	authStore := &tokenRollbackAuth{}
	s := &Server{
		Auth:  authStore,
		flash: newFlashStore(failingFlashBackend{}),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	req := httptest.NewRequest(http.MethodPost, "/tokens", strings.NewReader("name=automation"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := withUser(req.Context(), auth.User{ID: "user_1", Role: auth.RoleAdmin})
	ctx = withSessionState(ctx, auth.SessionState{IDHash: "test-session"})
	ctx = withSessionCookie(ctx, "test-session-cookie")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.tokensCreate(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if authStore.revokedTokenID != "tok_new" || authStore.revokedUserID != "user_1" {
		t.Fatalf("revoked = (%q, %q), want (tok_new, user_1)", authStore.revokedTokenID, authStore.revokedUserID)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("flash failure wrote browser capability: %+v", cookies)
	}
}
