package journal

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestPostgresNotificationConfigEnvelopeAndOldWriterCutover(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL notification config test")
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
	schema := fmt.Sprintf("notification_crypto_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	scopedURL := u.String()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), scopedURL); err != nil {
		t.Fatal(err)
	}
	db, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := New(db, EnginePostgres)
	legacy, err := j.CreateNotificationChannelInTenant(ctx, "acme", "legacy", ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid/legacy"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x70}, 32), nil); err != nil {
		t.Fatal(err)
	}
	const secret = "synthetic-pg-private-channel"
	config := json.RawMessage(`{"url":"https://example.invalid/hook","headers":{"X-Token":"` + secret + `"}}`)
	id, err := j.CreateNotificationChannelInTenant(ctx, "acme", "encrypted", ChannelKindGenericWebhook, config)
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	var version, plainBytes int
	if err := db.QueryRowContext(ctx, `SELECT config_json::text, config_crypto_version, config_plaintext_bytes
		FROM notification_channels WHERE id = $1`, id).Scan(&raw, &version, &plainBytes); err != nil {
		t.Fatal(err)
	}
	if version != 1 || plainBytes != len(config) || strings.Contains(raw, secret) || !strings.Contains(raw, "__reactor_payload_envelope") {
		t.Fatalf("PG config persisted plaintext: version=%d bytes=%d", version, plainBytes)
	}
	got, err := j.GetNotificationChannel(ctx, id)
	if err != nil || !bytes.Equal(got.ConfigJSON, config) {
		t.Fatalf("PG channel = %+v, %v", got, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO notification_channels (id, tenant_id, name, kind, config_json)
		VALUES ($1, $2, $3, $4, $5)`, "nch_pg_old", "acme", "old-writer", ChannelKindGenericWebhook, `{"url":"https://example.invalid/old"}`); err == nil || !strings.Contains(err.Error(), "encrypted notification config required") {
		t.Fatalf("PG old insert = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE notification_channels SET config_json = $1 WHERE id = $2`, `{"url":"https://example.invalid/changed"}`, legacy); err == nil || !strings.Contains(err.Error(), "encrypted notification config required") {
		t.Fatalf("PG old update = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE notification_channels SET config_json = $1::jsonb WHERE id = $2`, raw, legacy); err == nil || !strings.Contains(err.Error(), "encrypted notification config required") {
		t.Fatalf("PG old copy to v0 = %v", err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_pg_notify", "pg-notify", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_pg_notify", id, "failed"); err != nil {
		t.Fatal(err)
	}
	channels, err := j.ChannelsForRunTerminal(ctx, "wf_pg_notify", "failed")
	if err != nil || len(channels) != 1 || !bytes.Equal(channels[0].ConfigJSON, config) {
		t.Fatalf("PG notifier lookup = %+v, %v", channels, err)
	}
}
