package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func seedProviderPermitConnection(t *testing.T, j *Journal, tenantID, providerID, connectionID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO oauth_providers
		(provider_id, auth_url, token_url, enabled) VALUES ($1, $2, $3, $4)
		ON CONFLICT (provider_id) DO NOTHING`),
		providerID, "https://auth.example.test", "https://token.example.test", j.boolValue(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, status)
		VALUES ($1, $2, $3, $4, $5, 'connected')`),
		connectionID, tenantID, providerID, connectionID, []byte("encrypted-test-blob")); err != nil {
		t.Fatal(err)
	}
}

func TestProviderPermitSharedAccountBudgetAndTenantIsolation(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	seedProviderPermitConnection(t, j, "tenant-a", "provider-a", "conn-a")
	seedProviderPermitConnection(t, j, "tenant-b", "provider-b", "conn-b")
	policy := ProviderPermitPolicy{RequestsPerMinute: 2, MaxConcurrent: 1}

	first, err := j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", policy)
	if err != nil || first.ID == "" {
		t.Fatalf("first account permit = %+v, %v", first, err)
	}
	_, err = j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", policy)
	var denied *ProviderPermitDeniedError
	if !errors.As(err, &denied) || denied.Reason != "concurrency" || denied.RetryAfter <= 0 {
		t.Fatalf("in-flight account refusal = %v, want concurrency with wait", err)
	}
	if _, err := j.AcquireProviderPermit(ctx, "tenant-b", "conn-a", policy); !errors.Is(err, ErrProviderAccountUnavailable) {
		t.Fatalf("foreign tenant account permit = %v, want unavailable", err)
	}
	other, err := j.AcquireProviderPermit(ctx, "tenant-b", "conn-b", policy)
	if err != nil {
		t.Fatalf("independent account permit: %v", err)
	}
	if err := j.CompleteProviderPermit(ctx, other, 0); err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteProviderPermit(ctx, first, 0); err != nil {
		t.Fatal(err)
	}
	second, err := j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", policy)
	if err != nil {
		t.Fatalf("second account permit after release: %v", err)
	}
	if err := j.CompleteProviderPermit(ctx, second, 0); err != nil {
		t.Fatal(err)
	}
	_, err = j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", policy)
	if !errors.As(err, &denied) || denied.Reason != "rate_limit" || denied.RetryAfter <= 0 {
		t.Fatalf("rolling-minute account refusal = %v, want rate limit", err)
	}
	_, err = j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", ProviderPermitPolicy{RequestsPerMinute: 3, MaxConcurrent: 1})
	if !errors.Is(err, ErrProviderPolicyMismatch) {
		t.Fatalf("changed worker policy = %v, want mismatch", err)
	}
	var count int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_account_permits WHERE tenant_id = 'tenant-a'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("charged provider attempts = %d, %v, want exactly two", count, err)
	}
}

func TestProviderPermitCooldownAndBoundedRetention(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	seedProviderPermitConnection(t, j, "tenant-a", "provider-a", "conn-a")
	policy := ProviderPermitPolicy{RequestsPerMinute: 2, MaxConcurrent: 1}
	first, err := j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteProviderPermit(ctx, first, time.Hour*48); err != nil {
		t.Fatal(err)
	}
	_, err = j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", policy)
	var denied *ProviderPermitDeniedError
	if !errors.As(err, &denied) || denied.Reason != "cooldown" || denied.RetryAfter > maxProviderCooldown {
		t.Fatalf("shared cooldown refusal = %v, want bounded cooldown", err)
	}
	// Move the test account's clock fields instead of sleeping through a
	// provider window. The next admission prunes a completed old receipt.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE provider_account_budgets SET cooldown_until = $1
		WHERE tenant_id = $2 AND connection_id = $3`), j.formatTime(time.Now().Add(-time.Minute)), "tenant-a", "conn-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE provider_account_permits SET granted_at = $1, expires_at = $2
		WHERE id = $3`), j.formatTime(time.Now().Add(-2*time.Minute)), j.formatTime(time.Now().Add(-time.Minute)), first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := j.AcquireProviderPermit(ctx, "tenant-a", "conn-a", policy)
	if err != nil {
		t.Fatalf("acquire after old receipt and cooldown expired: %v", err)
	}
	var count int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM provider_account_permits WHERE tenant_id = 'tenant-a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retained permit rows = %d, %v, want one current receipt", count, err)
	}
	if err := j.CompleteProviderPermit(ctx, second, 0); err != nil {
		t.Fatal(err)
	}
}

func TestProviderPermitFailsClosedOnDatabaseError(t *testing.T) {
	j, cleanup := newTestJournal(t)
	seedProviderPermitConnection(t, j, "tenant-a", "provider-a", "conn-a")
	cleanup()
	if permit, err := j.AcquireProviderPermit(context.Background(), "tenant-a", "conn-a", ProviderPermitPolicy{RequestsPerMinute: 2, MaxConcurrent: 1}); err == nil || permit.ID != "" {
		t.Fatalf("closed database permit = %+v, %v, want no permit", permit, err)
	}
}

func TestPostgresProviderPermitConcurrentWorkersShareAccountBudget(t *testing.T) {
	rawURL := requireProviderTestPostgresURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	suffix := strings.ReplaceAll(fmt.Sprint(time.Now().UTC().UnixNano()), "-", "")
	providerID, connectionID := "permit-provider-"+suffix, "permit-conn-"+suffix
	seedProviderPermitConnection(t, j, "tenant-a", providerID, connectionID)
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oauth_connections WHERE id = $1`, connectionID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oauth_providers WHERE provider_id = $1`, providerID)
	}()
	policy := ProviderPermitPolicy{RequestsPerMinute: 10, MaxConcurrent: 1}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := j.AcquireProviderPermit(ctx, "tenant-a", connectionID, policy)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded, refused := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
			continue
		}
		var denied *ProviderPermitDeniedError
		if !errors.As(err, &denied) || denied.Reason != "concurrency" {
			t.Fatalf("concurrent account admission = %v, want concurrency refusal", err)
		}
		refused++
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("concurrent account admission = %d success, %d refused; want 1/1", succeeded, refused)
	}
}
