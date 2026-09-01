package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/vault"
)

const testMasterHex = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc1"

func newCmdEnv(t *testing.T) (dbURL string, repo *credentials.Repo, store *vault.Store, masterHex string) {
	t.Helper()
	dir := t.TempDir()
	dbURL = "sqlite://" + filepath.Join(dir, "v.db")

	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, dbURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	masterHex = testMasterHex[:64]

	repo, _, err := openCredentials(dbURL)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}

	store, _, err = openVaultStore(dbURL, masterHex)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return dbURL, repo, store, masterHex
}

func TestCmdVaultListEmptyAndPopulated(t *testing.T) {
	t.Parallel()
	dbURL, repo, _, _ := newCmdEnv(t)
	if err := cmdVault(context.Background(), discardLogger(), []string{"list", "--db", dbURL}); err != nil {
		t.Fatalf("empty list: %v", err)
	}

	id, _ := credentials.NewID()
	if err := repo.Create(context.Background(), credentials.CreateParams{
		ID: id, Name: "demo", Service: "x", Provider: "shared-secret",
		AutoRotate: true, RotationIntervalDays: 30,
	}); err != nil {
		t.Fatal(err)
	}

	if err := cmdVault(context.Background(), discardLogger(), []string{"list", "--db", dbURL}); err != nil {
		t.Fatalf("populated list: %v", err)
	}
	if err := cmdVault(context.Background(), discardLogger(), []string{"list", "--db", dbURL, "--json"}); err != nil {
		t.Fatalf("json list: %v", err)
	}
}

func TestCmdVaultRotateSharedSecretE2E(t *testing.T) {
	t.Parallel()
	dbURL, repo, store, masterHex := newCmdEnv(t)
	ctx := context.Background()

	// HMAC secret used to sign delivery requests.
	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_hmac", Name: "hmac", Service: "internal", Provider: "manual",
	}); err != nil {
		t.Fatal(err)
	}
	const sharedSecret = "shared-hmac-shhh"
	if err := store.Put(ctx, "cred_hmac", []byte(sharedSecret)); err != nil {
		t.Fatal(err)
	}

	// Webhook target captures + validates the signed payload.
	var hits atomic.Int32
	var sigOK atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		got := strings.TrimPrefix(r.Header.Get("X-Reactor-Signature"), "sha256=")
		want := hmac.New(sha256.New, []byte(sharedSecret))
		want.Write(body)
		if hex.EncodeToString(want.Sum(nil)) == got {
			sigOK.Store(true)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// The rotating credential.
	if err := repo.Create(ctx, credentials.CreateParams{
		ID: "cred_app", Name: "app", Service: "internal", Provider: "shared-secret",
		AutoRotate: true, RotationIntervalDays: 1,
		RotationTargets: []credentials.Target{
			{Kind: "webhook", URL: srv.URL, SecretID: "cred_hmac", KeyName: "APP_SECRET"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cred_app", []byte("v0")); err != nil {
		t.Fatal(err)
	}

	// Drive cmdVault rotate against the live binary code path.
	if err := cmdVault(ctx, discardLogger(), []string{"rotate", "--db", dbURL, "--master-key", masterHex, "cred_app"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("delivery hits = %d, want 1", hits.Load())
	}
	if !sigOK.Load() {
		t.Fatal("HMAC signature didn't verify")
	}

	// Audit list must show the chain.
	if err := cmdVault(ctx, discardLogger(), []string{"audit", "--db", dbURL, "cred_app", "--json"}); err != nil {
		t.Fatalf("audit json: %v", err)
	}
	rows, err := repo.ListAudit(ctx, "cred_app", 50)
	if err != nil {
		t.Fatal(err)
	}
	gotActions := map[string]bool{}
	for _, r := range rows {
		gotActions[r.Action] = true
		// Ensure detail is valid JSON so the JSON output is stable.
		var probe map[string]any
		if err := json.Unmarshal(r.Detail, &probe); err != nil {
			t.Fatalf("audit row detail not json: %s", string(r.Detail))
		}
	}
	for _, want := range []string{"rotate.start", "rotate.success", "rotate.delivery_success"} {
		if !gotActions[want] {
			t.Fatalf("missing audit action %q", want)
		}
	}
}

func TestCmdVaultRotateMissingMasterKey(t *testing.T) {
	t.Parallel()
	dbURL, _, _, _ := newCmdEnv(t)
	err := cmdVault(context.Background(), discardLogger(), []string{"rotate", "--db", dbURL, "cred_x"})
	if err == nil || !strings.Contains(err.Error(), "master-key") {
		t.Fatalf("got %v, want master-key error", err)
	}
}

func TestCmdVaultUnknownSub(t *testing.T) {
	t.Parallel()
	if err := cmdVault(context.Background(), discardLogger(), []string{"frobnicate"}); err == nil ||
		!strings.Contains(err.Error(), "unknown subcommand") {
		t.Fatalf("got %v, want unknown subcommand", err)
	}
}

// TestCmdVaultAddSeedsRotatableCredential drives `vault add` end-to-end
// against a temp DB + master key. Verifies the credential is listed and
// the encrypted blob round-trips through vault.Store.
func TestCmdVaultAddSeedsRotatableCredential(t *testing.T) {
	t.Parallel()
	dbURL, _, _, masterHex := newCmdEnv(t)
	ctx := context.Background()

	if err := cmdVault(ctx, discardLogger(), []string{
		"add",
		"--db", dbURL,
		"--master-key", masterHex,
		"--name", "crm-api-key",
		"--service", "crm",
		"--provider", "shared-secret",
		"--auto-rotate",
		"--interval-days", "30",
		"--value", "demo-secret",
	}); err != nil {
		t.Fatalf("vault add: %v", err)
	}

	store, _, err := openVaultStore(dbURL, masterHex)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	sec, err := store.Get(ctx, "crm-api-key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(sec.Reveal()) != "demo-secret" {
		t.Fatalf("plaintext mismatch: %q", sec.Reveal())
	}
}

func TestCmdVaultAddAssignsTenantAndStoresByCredentialID(t *testing.T) {
	t.Parallel()
	dbURL, repo, _, masterHex := newCmdEnv(t)
	ctx := context.Background()

	if err := cmdVault(ctx, discardLogger(), []string{
		"add",
		"--db", dbURL,
		"--master-key", masterHex,
		"--tenant", "acme",
		"--id", "cred_crm",
		"--name", "crm-api-key",
		"--value", "tenant-secret",
	}); err != nil {
		t.Fatalf("vault add: %v", err)
	}
	credential, err := repo.Get(ctx, "cred_crm")
	if err != nil {
		t.Fatal(err)
	}
	if credential.TenantID != "acme" {
		t.Fatalf("tenant = %q, want acme", credential.TenantID)
	}
	store, closer, err := openVaultStore(dbURL, masterHex)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	secret, err := store.Get(ctx, "cred_crm")
	if err != nil {
		t.Fatalf("get by credential id: %v", err)
	}
	if string(secret.Reveal()) != "tenant-secret" {
		t.Fatalf("secret = %q", secret.Reveal())
	}
	if _, err := repo.Get(ctx, "crm-api-key"); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("vault add created an unintended name-keyed credential: %v", err)
	}
}

func TestCmdVaultGrantScopesDuplicateSlugByTenant(t *testing.T) {
	t.Parallel()
	dbURL, repo, _, _ := newCmdEnv(t)
	ctx := context.Background()
	j, closer, err := openJournal(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if err := j.CreateWorkflowInTenant(ctx, "wf_acme", "shared", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_globex", "shared", "h", "1", json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []credentials.CreateParams{
		{ID: "cred_acme", Name: "cred_acme", TenantID: "acme"},
		{ID: "cred_globex", Name: "cred_globex", TenantID: "globex"},
	} {
		if err := repo.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	if err := cmdVaultGrant(ctx, discardLogger(), []string{
		"--db", dbURL, "--tenant", "acme", "shared", "cred_acme",
	}); err != nil {
		t.Fatalf("tenant-scoped grant: %v", err)
	}
	if ok, err := j.HasGrant(ctx, "wf_acme", "cred_acme"); err != nil || !ok {
		t.Fatalf("acme grant = %t, %v", ok, err)
	}
	if ok, err := j.HasGrant(ctx, "wf_globex", "cred_acme"); err != nil || ok {
		t.Fatalf("globex unexpectedly received acme grant = %t, %v", ok, err)
	}

	err = cmdVaultGrant(ctx, discardLogger(), []string{
		"--db", dbURL, "--tenant", "globex", "shared", "cred_acme",
	})
	if err == nil || !strings.Contains(err.Error(), "cross-tenant") {
		t.Fatalf("cross-tenant grant error = %v", err)
	}
	// The default is deliberately scoped to the default tenant rather than
	// falling back to whichever duplicate slug was registered most recently.
	err = cmdVaultGrant(ctx, discardLogger(), []string{
		"--db", dbURL, "shared", "cred_globex",
	})
	if err == nil || !strings.Contains(err.Error(), `tenant "default"`) {
		t.Fatalf("default tenant grant error = %v", err)
	}
}

func TestCmdVaultAddRequiredFlags(t *testing.T) {
	t.Parallel()
	dbURL, _, _, masterHex := newCmdEnv(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing --name",
			args: []string{"add", "--db", dbURL, "--master-key", masterHex, "--value", "v"},
			want: "--name",
		},
		{
			name: "missing --value",
			args: []string{"add", "--db", dbURL, "--master-key", masterHex, "--name", "n"},
			want: "--value",
		},
		{
			name: "auto-rotate without interval",
			args: []string{"add", "--db", dbURL, "--master-key", masterHex, "--name", "n", "--value", "v", "--auto-rotate"},
			want: "interval-days",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := cmdVault(context.Background(), discardLogger(), tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}
