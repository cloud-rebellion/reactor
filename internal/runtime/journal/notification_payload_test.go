package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestNotificationConfigEnvelopeLegacyAndOldWriterFence(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	legacyConfig := json.RawMessage(`{"url":"https://example.invalid/legacy"}`)
	legacyID, err := j.CreateNotificationChannelInTenant(ctx, "acme", "legacy", ChannelKindGenericWebhook, legacyConfig)
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x68}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	const secret = "synthetic-channel-secret-å界"
	config := json.RawMessage(`{"url":"https://example.invalid/hook","headers":{"X-Token":"` + secret + `"}}`)
	id, err := j.CreateNotificationChannelInTenant(ctx, "acme", "encrypted", ChannelKindGenericWebhook, config)
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var version, plainBytes int
	if err := j.db.QueryRowContext(ctx, `SELECT config_json, config_crypto_version, config_plaintext_bytes FROM notification_channels WHERE id = ?`, id).Scan(&stored, &version, &plainBytes); err != nil {
		t.Fatal(err)
	}
	if version != 1 || plainBytes != len(config) || bytes.Contains(stored, []byte(secret)) || !bytes.Contains(stored, []byte("__reactor_payload_envelope")) {
		t.Fatalf("unsafe channel config: version=%d bytes=%d stored=%s", version, plainBytes, stored)
	}
	got, err := j.GetNotificationChannel(ctx, id)
	if err != nil || !bytes.Equal(got.ConfigJSON, config) {
		t.Fatalf("keyed channel = %+v, %v", got, err)
	}
	legacy, err := j.GetNotificationChannel(ctx, legacyID)
	if err != nil || !bytes.Equal(legacy.ConfigJSON, legacyConfig) {
		t.Fatalf("legacy channel = %+v, %v", legacy, err)
	}
	page, more, err := j.ListNotificationChannelsByTenantPage(ctx, "acme", 2, 0)
	if err != nil || more || len(page) != 2 {
		t.Fatalf("full channel page = %+v more=%v err=%v", page, more, err)
	}
	reader := New(j.db, EngineSQLite)
	if err := reader.LoadPayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if reopened, err := reader.GetNotificationChannel(ctx, id); err != nil || !bytes.Equal(reopened.ConfigJSON, config) {
		t.Fatalf("restarted channel = %+v, %v", reopened, err)
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.GetNotificationChannel(ctx, id); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed channel read = %v", err)
	}
	if _, err := unkeyed.CreateNotificationChannelInTenant(ctx, "acme", "old-writer", ChannelKindGenericWebhook, legacyConfig); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed channel writer = %v", err)
	}
	metadata, _, err := unkeyed.ListNotificationChannelMetadataByTenantPage(ctx, "acme", 10, 0)
	if err != nil || len(metadata) != 2 {
		t.Fatalf("keyless metadata = %+v, %v", metadata, err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO notification_channels (id, tenant_id, name, kind, config_json)
		VALUES (?, ?, ?, ?, ?)`, "nch_old_writer", "acme", "old-writer-raw", ChannelKindGenericWebhook, string(legacyConfig)); err == nil {
		t.Fatal("old SQL writer inserted plaintext after key initialization")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE notification_channels SET config_json = ? WHERE id = ?`, `{"url":"https://example.invalid/changed"}`, legacyID); err == nil {
		t.Fatal("old SQL writer changed legacy plaintext config after key initialization")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE notification_channels SET config_crypto_version = 0, config_plaintext_bytes = NULL, config_json = ? WHERE id = ?`, string(legacyConfig), id); err == nil {
		t.Fatal("encrypted config downgraded to plaintext")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE notification_channels SET config_json = ? WHERE id = ?`, string(stored), legacyID); err == nil {
		t.Fatal("old SQL writer copied encrypted config into legacy version zero")
	}
	otherID, err := j.CreateNotificationChannelInTenant(ctx, "acme", "other", ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid/other"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE notification_channels SET config_json = ? WHERE id = ?`, string(stored), otherID); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetNotificationChannel(ctx, otherID); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("copied envelope authenticated under another channel: %v", err)
	}
	var legacyVersion int
	if err := j.db.QueryRowContext(ctx, `SELECT config_crypto_version FROM notification_channels WHERE id = ?`, legacyID).Scan(&legacyVersion); err != nil {
		t.Fatal(err)
	}
	if legacyVersion != 0 {
		t.Fatalf("legacy config falsely backfilled: version=%d", legacyVersion)
	}
}

func TestTerminalNotificationLookupSkipsUnmatchedConfig(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x69}, 32), nil); err != nil {
		t.Fatal(err)
	}
	unmatched, err := j.CreateNotificationChannel(ctx, "unmatched", ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid/unmatched"}`))
	if err != nil {
		t.Fatal(err)
	}
	matching, err := j.CreateNotificationChannel(ctx, "matching", ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid/matching"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_1", unmatched, "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_1", matching, "failed"); err != nil {
		t.Fatal(err)
	}
	// Both rows retain a valid envelope shape; copying a ciphertext breaks AAD.
	// A failed-run lookup must not open the unrelated succeeded-only channel.
	var copied []byte
	if err := j.db.QueryRowContext(ctx, `SELECT config_json FROM notification_channels WHERE id = ?`, matching).Scan(&copied); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE notification_channels SET config_json = ? WHERE id = ?`, string(copied), unmatched); err != nil {
		t.Fatal(err)
	}
	channels, err := j.ChannelsForRunTerminal(ctx, "wf_1", "failed")
	if err != nil || len(channels) != 1 || channels[0].ID != matching || !strings.Contains(string(channels[0].ConfigJSON), "/matching") {
		t.Fatalf("matched channels = %+v, %v", channels, err)
	}
	if _, err := j.ChannelsForRunTerminal(ctx, "wf_1", "succeeded"); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered matched channel = %v", err)
	}
}
