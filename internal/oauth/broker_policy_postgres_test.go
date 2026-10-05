package oauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestPostgresBrokerPolicyReviewAndIrreversibleMode(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL broker policy contract")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("oauth_broker_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scopedURL := u.String()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, scopedURL); err != nil {
		t.Fatal(err)
	}
	db, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	store := New(db, EnginePostgres, key)
	if err := store.UpsertProvider(ctx, Provider{ProviderID: "acme-pg", Name: "Acme",
		AuthURL: "https://login.acme.example/auth", TokenURL: "https://login.acme.example/token", Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := store.upsertConnection(ctx, "tenant-pg", "acme-pg", "main", "operator", tokenBlob{AccessToken: "pg-token"})
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := store.RawTokenAllowed(ctx, conn.ID, "tenant-pg"); err != nil || allowed {
		t.Fatalf("new PostgreSQL connection raw eligible=%v err=%v", allowed, err)
	}
	policy, err := store.ApproveBrokerPolicy(ctx, "tenant-pg", conn.ID, "reviewer", 0,
		"https://api.acme.example", "/v1", "GET")
	if err != nil || policy.Version != 1 {
		t.Fatalf("PostgreSQL approval=%+v err=%v", policy, err)
	}
	session, err := store.GenericBrokerSession(ctx, "tenant-pg", conn.ID)
	if err != nil || session.BearerToken() != "pg-token" {
		t.Fatalf("PostgreSQL broker session=%v err=%v", session, err)
	}
	if current, err := store.BrokerPolicyCurrent(ctx, session); err != nil || !current {
		t.Fatalf("PostgreSQL review current=%v err=%v", current, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE oauth_connections SET token_access_mode='legacy_raw' WHERE id=$1`, conn.ID); err == nil {
		t.Fatal("PostgreSQL broker-only mode downgraded")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM oauth_api_policies WHERE connection_id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GenericBrokerSession(ctx, "tenant-pg", conn.ID); !errors.Is(err, ErrBrokerPolicyUnavailable) {
		t.Fatalf("deleted PostgreSQL policy brokered: %v", err)
	}
	if allowed, err := store.RawTokenAllowed(ctx, conn.ID, "tenant-pg"); err != nil || allowed {
		t.Fatalf("deleted PostgreSQL policy reenabled raw=%v err=%v", allowed, err)
	}
}
