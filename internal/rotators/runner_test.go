package rotators

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

// newE2EEnv stands up an isolated sqlite + vault.Store + credentials
// repo wired together the same way the daemon will run them. Tests use
// this rather than mocks so the rotation pipeline runs against real
// SQL + crypto.
func newE2EEnv(t *testing.T) (*credentials.Repo, *vault.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rot.db")
	url := "sqlite://" + dbPath
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo := credentials.New(db, credentials.EngineSQLite)

	master := make([]byte, 32)
	for i := range master {
		master[i] = 0xCC
	}
	backend := vault.NewSQLBackend(db, vault.SQLEngineSQLite)
	store, err := vault.NewStore(backend, master)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	return repo, store, func() { db.Close() }
}

// TestRunnerEndToEndSharedSecret stitches every layer together: a
// shared-secret credential with a webhook target. The runner mints a
// new value, persists it through vault.Store, the SQL backend writes
// the new blob, and the target receives the HMAC-signed POST.
func TestRunnerEndToEndSharedSecret(t *testing.T) {
	t.Parallel()
	repo, store, cleanup := newE2EEnv(t)
	defer cleanup()
	ctx := context.Background()

	// Seed an HMAC secret used by the delivery target's signature.
	// Order matters: create the metadata row first, then put the value.
	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_hmac", Name: "delivery-hmac", Service: "internal",
		Provider: "manual",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cred_hmac", []byte("hmac-secret-for-target")); err != nil {
		t.Fatal(err)
	}

	// Webhook receiver records what it sees.
	var hits atomic.Int32
	var lastPayload []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		lastPayload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// Seed the rotating credential (row first, then vault value).
	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_app", Name: "app-shared-secret", Service: "internal",
		Provider:             "shared-secret",
		AllowLocalMint:       true,
		AutoRotate:           true,
		RotationIntervalDays: 1,
		RotationTargets: []credentials.Target{
			{Kind: "webhook", URL: srv.URL, SecretID: "cred_hmac", KeyName: "APP_SHARED_SECRET"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cred_app", []byte("initial-secret")); err != nil {
		t.Fatal(err)
	}

	runner := &Runner{
		Repo:  repo,
		Vault: store,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:   func() time.Time { return time.Now() },
	}
	if err := runner.RotateOne(ctx, "cred_app"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if hits.Load() != 1 {
		t.Fatalf("target hits = %d, want 1", hits.Load())
	}
	if len(lastPayload) == 0 {
		t.Fatal("target received empty body")
	}

	// Vault must hold a new value.
	got, err := store.Get(ctx, "cred_app")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Reveal()) == "initial-secret" {
		t.Fatal("vault still holds old value")
	}

	// Audit log must contain start, success, delivery_success.
	rows, err := repo.ListAudit(ctx, "cred_app", 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Action] = true
	}
	for _, want := range []string{"rotate.start", "rotate.success", "rotate.delivery_success"} {
		if !seen[want] {
			t.Fatalf("missing audit action %q (got %v)", want, keys(seen))
		}
	}

	// Credential row: last_rotated_at set, last_rotation_error empty.
	c, _ := repo.Get(ctx, "cred_app")
	if c.LastRotatedAt.IsZero() {
		t.Fatal("last_rotated_at not set")
	}
	if c.LastRotationError != "" {
		t.Fatalf("last_rotation_error not cleared: %q", c.LastRotationError)
	}
}

func TestRunnerLocalMintRequiresAcknowledgement(t *testing.T) {
	t.Parallel()
	repo, store, cleanup := newE2EEnv(t)
	defer cleanup()
	ctx := context.Background()
	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_unack", Name: "unacknowledged", Service: "external", Provider: "shared-secret",
		AutoRotate: true, RotationIntervalDays: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cred_unack", []byte("externally-issued")); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{Repo: repo, Vault: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := runner.Tick(ctx); err != nil {
		t.Fatalf("scheduler tick should record the refusal and continue: %v", err)
	}
	unchanged, err := store.Get(ctx, "cred_unack")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(unchanged.Reveal()); got != "externally-issued" {
		t.Fatalf("unacknowledged scheduled rotation changed the stored value to %q", got)
	}
	c, err := repo.Get(ctx, "cred_unack")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.LastRotationError, "local_mint_ack_required") {
		t.Fatalf("scheduler refusal did not record its policy error: %q", c.LastRotationError)
	}
	if err := runner.RotateOneWithLocalMintAck(ctx, "cred_unack", true); err != nil {
		t.Fatalf("explicitly acknowledged local mint: %v", err)
	}
	rotated, err := store.Get(ctx, "cred_unack")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(rotated.Reveal()); got == "externally-issued" || got == "" {
		t.Fatalf("acknowledged rotation did not replace value: %q", got)
	}
}

// TestRunnerDeliveryFailureStampsError verifies the runner logs each
// failed target separately and stamps last_rotation_error so the CLI
// surface shows "X of Y delivery target(s) failed".
func TestRunnerDeliveryFailureStampsError(t *testing.T) {
	t.Parallel()
	repo, store, cleanup := newE2EEnv(t)
	defer cleanup()
	ctx := context.Background()

	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_hmac", Name: "delivery-hmac", Service: "internal", Provider: "manual",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cred_hmac", []byte("hmac-secret")); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_app", Name: "app", Service: "internal", Provider: "shared-secret",
		AllowLocalMint: true,
		AutoRotate:     true, RotationIntervalDays: 1,
		RotationTargets: []credentials.Target{
			{Kind: "webhook", URL: srv.URL, SecretID: "cred_hmac", KeyName: "K"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cred_app", []byte("v0")); err != nil {
		t.Fatal(err)
	}

	runner := &Runner{Repo: repo, Vault: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := runner.RotateOne(ctx, "cred_app"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	c, _ := repo.Get(ctx, "cred_app")
	if c.LastRotationError == "" {
		t.Fatal("expected last_rotation_error to be stamped on delivery failure")
	}
	rows, _ := repo.ListAudit(ctx, "cred_app", 50)
	failuresSeen := false
	for _, r := range rows {
		if r.Action == "rotate.delivery_failure" {
			failuresSeen = true
			break
		}
	}
	if !failuresSeen {
		t.Fatal("expected rotate.delivery_failure audit row")
	}
}

// TestRunnerManualProviderEmitsReminder verifies that credentials with
// a manual provider don't break the runner; they emit a reminder audit
// row instead.
func TestRunnerManualProviderEmitsReminder(t *testing.T) {
	t.Parallel()
	repo, store, cleanup := newE2EEnv(t)
	defer cleanup()
	ctx := context.Background()

	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_pat", Name: "github-pat", Service: "github",
		Provider: "manual", AutoRotate: true, RotationIntervalDays: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cred_pat", []byte("github-pat")); err != nil {
		t.Fatal(err)
	}

	runner := &Runner{Repo: repo, Vault: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := runner.RotateOne(ctx, "cred_pat"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rows, _ := repo.ListAudit(ctx, "cred_pat", 10)
	found := false
	for _, r := range rows {
		if r.Action == "rotate.reminder" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected rotate.reminder audit row for manual provider")
	}
}

// TestRunnerTickProcessesAllDue confirms Tick walks ListNeedingRotation
// and rotates each due credential once.
func TestRunnerTickProcessesAllDue(t *testing.T) {
	t.Parallel()
	repo, store, cleanup := newE2EEnv(t)
	defer cleanup()
	ctx := context.Background()

	_ = repo.Create(ctx, credentials.CreateParams{ID: "cred_hmac", Name: "h", Service: "i", Provider: "manual"})
	if err := store.Put(ctx, "cred_hmac", []byte("h")); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		id := []string{"cred_a", "cred_b", "cred_c"}[i]
		if err := repo.Create(ctx, credentials.CreateParams{
			ID: id, Name: id, Service: "x", Provider: "shared-secret",
			AllowLocalMint: true,
			AutoRotate:     true, RotationIntervalDays: 1,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.Put(ctx, id, []byte("v0")); err != nil {
			t.Fatal(err)
		}
	}

	// Concurrency=1 keeps the test deterministic against modernc/sqlite's
	// single-writer constraint; production defaults to 4 and the SQL
	// driver retries with busy_timeout, but here we want a clean assert.
	runner := &Runner{Repo: repo, Vault: store, Concurrency: 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := runner.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	for _, id := range []string{"cred_a", "cred_b", "cred_c"} {
		c, _ := repo.Get(ctx, id)
		if c.LastRotatedAt.IsZero() {
			t.Fatalf("%s not rotated", id)
		}
		got, _ := store.Get(ctx, id)
		if string(got.Reveal()) == "v0" {
			t.Fatalf("%s still has old value", id)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
