package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func requireProviderTestPostgresURL(t *testing.T) string {
	t.Helper()
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for the PostgreSQL provider permit tests")
	}
	// These tests migrate and write the target database. Refuse non-Postgres
	// URLs and names that do not explicitly identify a test database before
	// connecting, matching the other PostgreSQL integration fixtures.
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL must target Postgres: engine=%q err=%v", engine, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(parsed.Path, "/")), "test") {
		t.Fatal("REACTOR_TEST_POSTGRES_URL database name must contain 'test'")
	}
	return rawURL
}

func TestSharedProviderPermitAcrossConnectionsAndTenantIsolation(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	seedProviderPermitConnection(t, j, "tenant-a", "salesforce", "conn-1")
	seedProviderPermitConnection(t, j, "tenant-a", "salesforce", "conn-2")
	seedProviderPermitConnection(t, j, "tenant-b", "salesforce", "conn-3")
	key := strings.Repeat("a", 64)
	otherKey := strings.Repeat("b", 64)
	policy := ProviderPermitPolicy{RequestsPerMinute: 2, MaxConcurrent: 1}

	first, err := j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-1", "salesforce", key, policy)
	if err != nil {
		t.Fatal(err)
	}
	_, err = j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-2", "salesforce", key, policy)
	var denied *ProviderPermitDeniedError
	if !errors.As(err, &denied) || denied.Reason != "concurrency" {
		t.Fatalf("second connection bypassed shared concurrency: %v", err)
	}
	if err := j.CompleteSharedProviderPermit(ctx, first, 0); err != nil {
		t.Fatal(err)
	}
	second, err := j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-2", "salesforce", key, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteSharedProviderPermit(ctx, second, 0); err != nil {
		t.Fatal(err)
	}
	_, err = j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-1", "salesforce", key, policy)
	if !errors.As(err, &denied) || denied.Reason != "rate_limit" {
		t.Fatalf("second connection bypassed shared rate: %v", err)
	}
	if _, err := j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-2", "salesforce", key,
		ProviderPermitPolicy{RequestsPerMinute: 3, MaxConcurrent: 1}); !errors.Is(err, ErrProviderPolicyMismatch) {
		t.Fatalf("changed worker policy = %v", err)
	}
	if _, err := j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-3", "salesforce", key, policy); !errors.Is(err, ErrProviderAccountUnavailable) {
		t.Fatalf("foreign tenant connection = %v", err)
	}
	for _, tc := range []struct{ tenant, conn, key string }{
		{"tenant-a", "conn-1", otherKey}, {"tenant-b", "conn-3", key},
	} {
		permit, err := j.AcquireSharedProviderPermit(ctx, tc.tenant, tc.conn, "salesforce", tc.key, policy)
		if err != nil {
			t.Fatalf("independent account/tenant = %v", err)
		}
		if err := j.CompleteSharedProviderPermit(ctx, permit, 0); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_shared_account_permits
		WHERE tenant_id = 'tenant-a' AND account_key = ?`, key).Scan(&count); err != nil || count != 2 {
		t.Fatalf("shared charged attempts = %d, %v", count, err)
	}
}

func TestSharedProviderPermitCooldownAndConnectionDeletion(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	seedProviderPermitConnection(t, j, "tenant-a", "salesforce", "conn-1")
	seedProviderPermitConnection(t, j, "tenant-a", "salesforce", "conn-2")
	key := strings.Repeat("c", 64)
	policy := ProviderPermitPolicy{RequestsPerMinute: 30, MaxConcurrent: 2}
	first, err := j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-1", "salesforce", key, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteSharedProviderPermit(ctx, first, 2*time.Minute); err != nil {
		t.Fatalf("persist shared cooldown: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `DELETE FROM oauth_connections WHERE id = 'conn-1'`); err != nil {
		t.Fatal(err)
	}
	_, err = j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-2", "salesforce", key, policy)
	var denied *ProviderPermitDeniedError
	if !errors.As(err, &denied) || denied.Reason != "cooldown" || denied.RetryAfter <= 0 {
		t.Fatalf("replacement connection bypassed cooldown: %v", err)
	}
	if _, err := j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-2", "google", key, policy); !errors.Is(err, ErrProviderAccountUnavailable) {
		t.Fatalf("wrong provider accepted: %v", err)
	}
	if _, err := j.AcquireSharedProviderPermit(ctx, "tenant-a", "conn-2", "salesforce", "workflow-input", policy); err == nil {
		t.Fatal("unvalidated account key accepted")
	}
}

func TestPostgresSharedProviderPermitConcurrentConnectionsShareOrg(t *testing.T) {
	rawURL := requireProviderTestPostgresURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test URL selected %s, want PostgreSQL", engine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprint(time.Now().UTC().UnixNano())
	tenantID := "shared-tenant-" + suffix
	providerID := "shared-provider-" + suffix
	connections := []string{"shared-conn-a-" + suffix, "shared-conn-b-" + suffix}
	for _, conn := range connections {
		seedProviderPermitConnection(t, j, tenantID, providerID, conn)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM provider_shared_account_budgets WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM oauth_connections WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM oauth_providers WHERE provider_id = $1`, providerID)
	}()
	policy := ProviderPermitPolicy{RequestsPerMinute: 10, MaxConcurrent: 1}
	key := strings.Repeat("d", 64)
	start := make(chan struct{})
	type result struct {
		permit SharedProviderPermit
		err    error
	}
	results := make(chan result, len(connections))
	var wg sync.WaitGroup
	for _, conn := range connections {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			permit, err := j.AcquireSharedProviderPermit(ctx, tenantID, conn, providerID, key, policy)
			results <- result{permit: permit, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded, refused := 0, 0
	for got := range results {
		if got.err == nil {
			succeeded++
			if err := j.CompleteSharedProviderPermit(ctx, got.permit, 0); err != nil {
				t.Fatal(err)
			}
			continue
		}
		var denied *ProviderPermitDeniedError
		if !errors.As(got.err, &denied) || denied.Reason != "concurrency" {
			t.Fatalf("concurrent shared admission = %v, want concurrency refusal", got.err)
		}
		refused++
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("concurrent shared admission = %d success, %d refused; want 1/1", succeeded, refused)
	}
}
