package credentials

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	_ "modernc.org/sqlite"
)

func newRepo(t *testing.T) (*Repo, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "c.db")
	url := "sqlite://" + dbPath

	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return New(db, EngineSQLite), func() { db.Close() }
}

func TestCreateAndGet(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()

	id, _ := NewID()
	if err := repo.Create(context.Background(), CreateParams{
		ID:                   id,
		Name:                 "demo-cf-token",
		Service:              "cloudflare",
		Provider:             "cloudflare",
		ProviderMeta:         map[string]string{"zone": "z1"},
		AutoRotate:           true,
		RotationIntervalDays: 30,
		RotationTargets: []Target{
			{Kind: "webhook", URL: "https://x", SecretID: "cred_hmac", KeyName: "CF_TOKEN"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	c, err := repo.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "demo-cf-token" || c.Provider != "cloudflare" || !c.AutoRotate ||
		c.RotationIntervalDays != 30 || len(c.RotationTargets) != 1 ||
		c.ProviderMeta["zone"] != "z1" {
		t.Fatalf("shape mismatch: %+v", c)
	}
}

func TestCreatePersistsLocalMintAcknowledgement(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	ctx := context.Background()
	if err := repo.Create(ctx, CreateParams{
		ID: "cred-local", Name: "local", Service: "internal", Provider: "shared-secret",
		AllowLocalMint: true,
	}); err != nil {
		t.Fatal(err)
	}
	c, err := repo.Get(ctx, "cred-local")
	if err != nil {
		t.Fatal(err)
	}
	if !LocalMintAcknowledged(c.ProviderMeta) {
		t.Fatalf("local-mint acknowledgement was not persisted: %#v", c.ProviderMeta)
	}
	if LocalMintAcknowledged(map[string]string{LocalMintAcknowledgementKey: "false"}) {
		t.Fatal("false acknowledgement must not pass")
	}
}

func TestGetMissing(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	if _, err := repo.Get(context.Background(), "cred_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestGetMetadataByTenantOmitsLargeProviderFieldsAndFencesTenant(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	ctx := context.Background()
	providerMeta := map[string]string{"endpoint": string(make([]byte, 2<<20))}
	if err := repo.Create(ctx, CreateParams{
		ID: "cred-metadata", Name: "metadata", TenantID: "acme",
		Service: "reactor-webhook", Provider: "shared-secret",
		ProviderMeta:    providerMeta,
		RotationTargets: []Target{{Kind: "webhook", URL: "https://example.invalid/hook", KeyName: "KEY", SecretID: "cred-auth"}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := repo.GetMetadataByTenant(ctx, "cred-metadata", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "cred-metadata" || got.TenantID != "acme" || got.Service != "reactor-webhook" || got.Provider != "shared-secret" {
		t.Fatalf("metadata identity mismatch: %+v", got)
	}
	if got.ProviderMeta != nil || got.RotationTargets != nil || got.LastRotationError != "" {
		t.Fatalf("metadata lookup materialized oversized/provider fields: %+v", got)
	}
	if _, err := repo.GetMetadataByTenant(ctx, "cred-metadata", "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant metadata lookup = %v, want ErrNotFound", err)
	}
}

func TestListMetadataPageIsBoundedAndOmitsSecretAdjacentColumns(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	ctx := context.Background()
	for _, p := range []CreateParams{
		{ID: "cred-a", TenantID: "acme", Name: "a", Service: "host", Provider: "shared-secret", ProviderMeta: map[string]string{"endpoint": strings.Repeat("x", 2<<20)}, RotationTargets: []Target{{Kind: "webhook", URL: "https://example.invalid", KeyName: "KEY", SecretID: "cred-auth"}}},
		{ID: "cred-b", TenantID: "globex", Name: "b", Service: "host", Provider: "shared-secret"},
	} {
		if err := repo.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.RecordError(ctx, "cred-a", strings.Repeat("diagnostic ", 200)); err != nil {
		t.Fatal(err)
	}
	page, more, err := repo.ListMetadataPage(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !more || len(page) != 1 || page[0].ID != "cred-a" {
		t.Fatalf("first metadata page = %#v, more=%v", page, more)
	}
	if page[0].ProviderMeta != nil || page[0].RotationTargets != nil || len(page[0].LastRotationError) > 512 {
		t.Fatalf("metadata page loaded unbounded/provider fields: %#v", page[0])
	}
	page, more, err = repo.ListMetadataPage(ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if more || len(page) != 1 || page[0].ID != "cred-b" {
		t.Fatalf("second metadata page = %#v, more=%v", page, more)
	}
}

func TestListNeedingRotation(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	ctx := context.Background()

	idAuto, _ := NewID()
	idManual, _ := NewID()

	if err := repo.Create(ctx, CreateParams{
		ID: idAuto, Name: "a", Service: "x", Provider: "shared-secret",
		AutoRotate: true, RotationIntervalDays: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, CreateParams{
		ID: idManual, Name: "b", Service: "x", Provider: "manual",
		AutoRotate: false, RotationIntervalDays: 30,
	}); err != nil {
		t.Fatal(err)
	}

	due, err := repo.ListNeedingRotation(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].ID != idAuto {
		t.Fatalf("expected [auto], got %d entries", len(due))
	}

	// After MarkRotated within the interval, no longer due.
	if err := repo.MarkRotated(ctx, idAuto, time.Now()); err != nil {
		t.Fatal(err)
	}
	due, err = repo.ListNeedingRotation(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Fatalf("expected none due after rotate, got %d", len(due))
	}

	// Past the interval, due again.
	due, err = repo.ListNeedingRotation(ctx, time.Now().Add(31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("expected 1 due past interval, got %d", len(due))
	}
}

func TestRecordErrorAndClear(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	ctx := context.Background()

	id, _ := NewID()
	if err := repo.Create(ctx, CreateParams{ID: id, Name: "n", Service: "s", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordError(ctx, id, "boom"); err != nil {
		t.Fatal(err)
	}
	c, _ := repo.Get(ctx, id)
	if c.LastRotationError != "boom" {
		t.Fatalf("error not stamped: %q", c.LastRotationError)
	}
	if err := repo.MarkRotated(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	c, _ = repo.Get(ctx, id)
	if c.LastRotationError != "" {
		t.Fatalf("error not cleared: %q", c.LastRotationError)
	}
}

func TestAuditAppendAndList(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	ctx := context.Background()

	id, _ := NewID()
	if err := repo.Create(ctx, CreateParams{ID: id, Name: "n", Service: "s", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	for i, action := range []string{"rotate.start", "rotate.success", "rotate.delivery_success"} {
		if err := repo.AppendAudit(ctx, AuditEntry{
			CredentialID: id,
			Action:       action,
			ActorKind:    "scheduler",
			Detail:       json.RawMessage(`{"i":"test"}`),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	rows, err := repo.ListAudit(ctx, id, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d audit rows, want 3", len(rows))
	}
	// Newest-first ordering.
	if rows[0].Action != "rotate.delivery_success" {
		t.Fatalf("expected newest first, got %s", rows[0].Action)
	}
}

func TestListAuditPageBoundedDoesNotMaterializeLargeDetail(t *testing.T) {
	t.Parallel()
	repo, cleanup := newRepo(t)
	defer cleanup()
	ctx := context.Background()
	if err := repo.Create(ctx, CreateParams{ID: "cred-bounded-audit", Name: "bounded", Service: "s", Provider: "shared-secret"}); err != nil {
		t.Fatal(err)
	}
	large := json.RawMessage(`{"error":"` + strings.Repeat("x", 4<<20) + `"}`)
	if err := repo.AppendAudit(ctx, AuditEntry{CredentialID: "cred-bounded-audit", Action: "rotate.failed", ActorKind: "scheduler", Detail: large}); err != nil {
		t.Fatal(err)
	}
	rows, err := repo.ListAuditPageBounded(ctx, "cred-bounded-audit", 10, 0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DetailBytes <= 4096 || !rows[0].DetailTruncated || len(rows[0].Detail) > 4096 {
		t.Fatalf("bounded audit row = len=%d bytes=%d truncated=%v", len(rows[0].Detail), rows[0].DetailBytes, rows[0].DetailTruncated)
	}
}
