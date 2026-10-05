package journal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestRunPayloadEncryptedAtRestReplayAndRotation(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const workflowID = "wf_payload_crypto"
	if err := j.CreateWorkflowInTenant(ctx, workflowID, "payload-crypto", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	legacy, err := j.GetRun(ctx, "run_1")
	if err != nil || string(legacy.ExecutionInput()) != "{}" {
		t.Fatalf("legacy run before key = %q, %v", legacy.ExecutionInput(), err)
	}
	masterA := bytes.Repeat([]byte{0x2a}, 32)
	masterB := bytes.Repeat([]byte{0x3b}, 32)
	if err := j.EnablePayloadEncryption(ctx, masterA, nil); err != nil {
		t.Fatal(err)
	}
	input := []byte(` { "private": "synthetic-customer-value-never-on-disk", "n": 1 } `)
	if err := j.CreateRun(ctx, "run_payload_crypto", workflowID, "manual", input); err != nil {
		t.Fatal(err)
	}
	var storedMeta, storedInput []byte
	var version int
	var plainBytes sql.NullInt64
	if err := j.db.QueryRowContext(ctx, `SELECT trigger_meta, trigger_input, payload_crypto_version, payload_plaintext_bytes
		FROM runs WHERE id = ?`, "run_payload_crypto").Scan(&storedMeta, &storedInput, &version, &plainBytes); err != nil {
		t.Fatal(err)
	}
	if version != 1 || !plainBytes.Valid || plainBytes.Int64 != int64(len(input)) ||
		bytes.Contains(storedMeta, []byte("synthetic-customer-value")) || bytes.Contains(storedInput, []byte("synthetic-customer-value")) ||
		!payloadcrypto.IsByteEnvelope(storedInput) {
		t.Fatalf("unsafe durable payload: version=%d bytes=%v meta=%q input=%q", version, plainBytes, storedMeta, storedInput)
	}
	read, err := j.GetRun(ctx, "run_payload_crypto")
	if err != nil || !bytes.Equal(read.ExecutionInput(), input) || !bytes.Equal(read.TriggerMeta, input) {
		t.Fatalf("worker read = %q, meta=%q, err=%v", read.ExecutionInput(), read.TriggerMeta, err)
	}
	meta, err := j.GetRunForTenantMetadata(ctx, "run_payload_crypto", "acme", len(input))
	if err != nil || !bytes.Equal(meta.TriggerMeta, input) || meta.TriggerMetaBytes != len(input) || meta.TriggerInputBytes != len(input) {
		t.Fatalf("MCP receipt = %+v, err=%v", meta, err)
	}
	bounded, err := j.GetRunForTenantInputBounded(ctx, "run_payload_crypto", "acme", len(input))
	if err != nil || !bytes.Equal(bounded.ExecutionInput(), input) {
		t.Fatalf("MCP exact input = %q, err=%v", bounded.ExecutionInput(), err)
	}
	adminRead, err := j.GetRunForTenantInputBounded(ctx, "run_payload_crypto", "", len(input))
	if err != nil || !bytes.Equal(adminRead.ExecutionInput(), input) {
		t.Fatalf("admin exact input = %q, err=%v", adminRead.ExecutionInput(), err)
	}
	if _, err := j.GetRunForTenantInputBounded(ctx, "run_payload_crypto", "acme", len(input)-1); !errors.Is(err, ErrRunInputTooLarge) {
		t.Fatalf("bounded input must refuse oversized plaintext: %v", err)
	}
	if _, err := j.GetRunForTenantInputBounded(ctx, "run_payload_crypto", "other", len(input)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign input read: %v", err)
	}

	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.GetRun(ctx, "run_payload_crypto"); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed replay: %v", err)
	}
	if err := unkeyed.CreateRun(ctx, "run_unkeyed_late", workflowID, "manual", []byte(`{}`)); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed late write: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO runs (id, workflow_id, trigger_kind, trigger_meta, status, tenant_id)
		VALUES (?, ?, 'manual', '{}', 'queued', 'acme')`, "run_old_binary", workflowID); err == nil || !strings.Contains(err.Error(), "encrypted run required") {
		t.Fatalf("old binary insert should be rejected by DB: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE runs SET payload_crypto_version = 0 WHERE id = ?`, "run_payload_crypto"); err == nil || !strings.Contains(err.Error(), "cannot become plaintext") {
		t.Fatalf("version downgrade should be rejected by DB: %v", err)
	}
	wrong := New(j.db, EngineSQLite)
	if err := wrong.LoadPayloadEncryption(ctx, masterB, nil); err == nil {
		t.Fatal("wrong master opened wrapped data key")
	}
	restarted := New(j.db, EngineSQLite)
	if err := restarted.LoadPayloadEncryption(ctx, masterA, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.GetRun(ctx, "run_payload_crypto"); err != nil || !bytes.Equal(got.ExecutionInput(), input) {
		t.Fatalf("restart replay = %q, %v", got.ExecutionInput(), err)
	}
	rotated := New(j.db, EngineSQLite)
	if err := rotated.EnablePayloadEncryption(ctx, masterB, masterA); err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.GetRun(ctx, "run_payload_crypto"); err != nil || !bytes.Equal(got.ExecutionInput(), input) {
		t.Fatalf("rotation replay = %q, %v", got.ExecutionInput(), err)
	}
	fresh := New(j.db, EngineSQLite)
	if err := fresh.LoadPayloadEncryption(ctx, masterB, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := fresh.GetRun(ctx, "run_payload_crypto"); err != nil || !bytes.Equal(got.ExecutionInput(), input) {
		t.Fatalf("post-rotation restart = %q, %v", got.ExecutionInput(), err)
	}
	if err := New(j.db, EngineSQLite).LoadPayloadEncryption(ctx, masterA, nil); err == nil {
		t.Fatal("retired master still opened rewrapped data key")
	}
	if got, err := fresh.GetRun(ctx, "run_1"); err != nil || string(got.ExecutionInput()) != "{}" {
		t.Fatalf("explicit legacy row after cutover = %q, %v", got.ExecutionInput(), err)
	}
}

func TestRunPayloadTamperingFailsClosed(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	master := bytes.Repeat([]byte{0x4c}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_payload_tamper", "wf_1", "manual", []byte(`{"secret":"original"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE runs SET trigger_input = ? WHERE id = ?`, []byte(`{"secret":"replacement"}`), "run_payload_tamper"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetRun(ctx, "run_payload_tamper"); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered worker input: %v", err)
	}
	if _, err := j.GetRunForTenant(ctx, "run_payload_tamper", "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign scoped read inspected or exposed a tampered payload: %v", err)
	}
	if _, err := j.GetRunForTenantInputBounded(ctx, "run_payload_tamper", "default", 1024); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered exact MCP export: %v", err)
	}
}
