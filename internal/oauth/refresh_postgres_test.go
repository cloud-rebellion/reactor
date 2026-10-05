package oauth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// Two daemon Store instances share only the PostgreSQL advisory lock, not a
// process-local gate. Keep this opt-in test for an isolated capacity database;
// SQLite cannot exercise the distributed refresh fence.
func TestPostgresStoresShareRotatingTokenRefreshLock(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL OAuth refresh race")
	}
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
		t.Fatalf("test URL selected %s, want postgres", engine)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	first := New(db, EnginePostgres, key)
	second := New(db, EnginePostgres, key)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	first.now, second.now = func() time.Time { return now }, func() time.Time { return now }
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	providerID := "oauth-refresh-" + suffix
	tenantID := "oauth-tenant-" + suffix
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oauth_connections WHERE tenant_id=$1`, tenantID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oauth_providers WHERE provider_id=$1`, providerID)
	}()
	if err := first.UpsertProvider(ctx, Provider{
		ProviderID: providerID, Name: "Test", AuthURL: "https://provider.example/auth",
		TokenURL: "https://provider.example/token", Enabled: true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := first.upsertConnection(ctx, tenantID, providerID, "account", "operator", tokenBlob{
		AccessToken: "expired", RefreshToken: "rotating-refresh", Expiry: now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var exchanges atomic.Int32
	client := &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		if exchanges.Add(1) == 1 {
			close(entered)
			<-release
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"fresh","refresh_token":"rotated-refresh","expires_in":3600}`)), Request: r}, nil
	})}
	first.http, second.http = client, client
	type result struct {
		token string
		err   error
	}
	done := make(chan result, 2)
	go func() { token, err := first.Token(ctx, conn.ID, tenantID); done <- result{token, err} }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() { token, err := second.Token(ctx, conn.ID, tenantID); done <- result{token, err} }()
	time.Sleep(30 * time.Millisecond)
	releaseOnce.Do(func() { close(release) })
	for i := 0; i < 2; i++ {
		select {
		case got := <-done:
			if got.err != nil || got.token != "fresh" {
				t.Fatalf("distributed token result = %+v", got)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if exchanges.Load() != 1 {
		t.Fatalf("rotating token exchanged %d times; want once", exchanges.Load())
	}
}
