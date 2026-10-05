package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestDeadLetterPayloadEncryptedAtRestAndTenantBounded(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_dlq_crypto", "dlq-crypto", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_dlq_crypto", "wf_dlq_crypto", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO dead_letter (id, run_id, step_name, error_text, payload, payload_crypto_version)
			VALUES ('dlq_bad_version', 'run_dlq_crypto', 'invalid', 'error', '{}', 2)`,
		`INSERT INTO dead_letter (id, run_id, step_name, error_text, payload, error_plaintext_bytes)
			VALUES ('dlq_bad_v0_length', 'run_dlq_crypto', 'invalid', 'error', '{}', 5)`,
	} {
		if _, err := j.db.ExecContext(ctx, statement); err == nil {
			t.Fatal("SQLite accepted an invalid dead-letter payload version or length")
		}
	}
	// A row written before first-key initialization stays explicit v0.
	if err := j.MoveStepToDeadLetter(ctx, "run_dlq_crypto", "legacy", "old failure", json.RawMessage(`{"legacy":true}`)); err != nil {
		t.Fatal(err)
	}
	masterA, masterB := bytes.Repeat([]byte{0x64}, 32), bytes.Repeat([]byte{0x65}, 32)
	if err := j.EnablePayloadEncryption(ctx, masterA, nil); err != nil {
		t.Fatal(err)
	}
	const failure = "private-dlq-error-20261004"
	payload := json.RawMessage(` { "private": "synthetic-dlq-value" } `)
	if err := j.MoveStepAttemptToDeadLetter(ctx, "run_dlq_crypto", "send", 4, 2, failure, payload); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_dlq_crypto")
	if err != nil || item.ErrorText != failure || !bytes.Equal(item.Payload, payload) ||
		item.StepSeq == nil || *item.StepSeq != 4 || item.StepAttempt == nil || *item.StepAttempt != 2 || item.FailureOrder != 2 {
		t.Fatalf("exact DLQ read = %+v, %v", item, err)
	}
	var storedError string
	var storedPayload []byte
	var version int
	var errorLen, payloadLen sql.NullInt64
	if err := j.db.QueryRowContext(ctx, `SELECT error_text, payload, payload_crypto_version,
		error_plaintext_bytes, payload_plaintext_bytes FROM dead_letter WHERE id = ?`, item.ID).
		Scan(&storedError, &storedPayload, &version, &errorLen, &payloadLen); err != nil {
		t.Fatal(err)
	}
	if version != 1 || !errorLen.Valid || errorLen.Int64 != int64(len(failure)) ||
		!payloadLen.Valid || payloadLen.Int64 != int64(len(payload)) ||
		strings.Contains(storedError, failure) || bytes.Contains(storedPayload, []byte("synthetic-dlq-value")) ||
		!payloadcrypto.IsByteEnvelope([]byte(storedError)) {
		t.Fatalf("unsafe DLQ storage: version=%d error=%q payload=%q lengths=%v/%v", version, storedError, storedPayload, errorLen, payloadLen)
	}
	if _, err := j.GetDeadLetterItemForTenant(ctx, item.ID, "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant could reach DLQ: %v", err)
	}
	if got, err := j.GetDeadLetterItemForTenant(ctx, item.ID, "acme"); err != nil || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("tenant exact DLQ = %+v, %v", got, err)
	}
	metadata, err := j.GetDeadLetterItemForTenantBounded(ctx, item.ID, "acme", 0, 0)
	if err != nil || !metadata.ErrorTruncated || !metadata.PayloadTruncated ||
		metadata.ErrorBytes != len(failure) || metadata.PayloadBytes != len(payload) ||
		metadata.ErrorText != "" || metadata.Payload != nil {
		t.Fatalf("metadata-only DLQ = %+v, %v", metadata, err)
	}
	bounded, err := j.GetDeadLetterItemForTenantBounded(ctx, item.ID, "acme", len(payload)-1, len(failure))
	if err != nil || bounded.ErrorText != failure || !bounded.PayloadTruncated || bounded.Payload != nil {
		t.Fatalf("bounded DLQ = %+v, %v", bounded, err)
	}
	full, err := j.GetDeadLetterItemForTenantBounded(ctx, item.ID, "acme", len(payload), len(failure))
	if err != nil || !bytes.Equal(full.Payload, payload) || full.ErrorText != failure {
		t.Fatalf("exact bounded DLQ = %+v, %v", full, err)
	}
	page, err := j.ListDeadLetterItemsForTenantPageBounded(ctx, 3, 0, "acme", 0, 0)
	if err != nil || len(page) != 2 || page[0].ID != item.ID || page[0].PayloadBytes != len(payload) {
		t.Fatalf("tenant DLQ inventory = %+v, %v", page, err)
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.GetDeadLetterItem(ctx, item.ID); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed full DLQ read = %v", err)
	}
	if err := unkeyed.MoveStepToDeadLetter(ctx, "run_dlq_crypto", "old-writer", "leak", json.RawMessage(`{}`)); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed journal writer = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO dead_letter
		(id, run_id, step_name, error_text, payload)
		VALUES (?, ?, 'old-binary', 'leak', '{}')`, "dlq_old_binary", "run_dlq_crypto"); err == nil || !strings.Contains(err.Error(), "encrypted dead_letter required") {
		t.Fatalf("old binary direct INSERT = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE dead_letter SET error_text = 'leak' WHERE step_name = 'legacy'`); err == nil || !strings.Contains(err.Error(), "encrypted dead_letter required") {
		t.Fatalf("old binary direct UPDATE = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE dead_letter SET error_text = 'leak' WHERE id = ?`, item.ID); err == nil {
		t.Fatal("old binary replaced keyed DLQ error with plaintext")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE dead_letter SET payload = '{}' WHERE id = ?`, item.ID); err == nil {
		t.Fatal("old binary replaced keyed DLQ payload with plaintext")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE dead_letter SET payload_crypto_version = 0 WHERE id = ?`, item.ID); err == nil {
		t.Fatal("encrypted DLQ version was downgraded")
	}
	rotated := New(j.db, EngineSQLite)
	if err := rotated.EnablePayloadEncryption(ctx, masterB, masterA); err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.GetDeadLetterItem(ctx, item.ID); err != nil || got.ErrorText != failure || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("post-rotation DLQ = %+v, %v", got, err)
	}
}

func TestDeadLetterPayloadTamperAndRedriveFailClosed(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x66}, 32), nil); err != nil {
		t.Fatal(err)
	}
	for seq, value := range []string{"aaaa", "bbbb"} {
		if err := j.MoveStepAttemptToDeadLetter(ctx, "run_1", "send", int64(seq+1), 1,
			"private-failure", json.RawMessage(`{"value":"`+value+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	items, err := j.ListDeadLetterItems(ctx, 10, 0)
	if err != nil || len(items) != 2 {
		t.Fatalf("seed DLQ = %+v, %v", items, err)
	}
	current, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil {
		t.Fatal(err)
	}
	other := items[0]
	if other.ID == current.ID {
		other = items[1]
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE dead_letter SET payload =
		(SELECT payload FROM dead_letter WHERE id = ?) WHERE id = ?`, other.ID, current.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetDeadLetterItem(ctx, current.ID); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("cross-row ciphertext swap = %v", err)
	}
	if _, err := j.GetDeadLetterItemForTenantBounded(ctx, current.ID, "default", 32, 32); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tenant export after swap = %v", err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	if ok, err := j.StartDeadLetterRetryItem(ctx, "run_1", current.ID); ok || !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered selected DLQ authorized redrive = %v, %v", ok, err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE dead_letter SET failure_order = 101 WHERE id = ?`, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetDeadLetterItem(ctx, other.ID); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("failure-order tamper = %v", err)
	}
}

func TestDeadLetterEncryptedLegacyPromotionAndStepRepair(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x67}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "legacy", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "legacy", 1, 1, nil, "private-legacy-failure"); err != nil {
		t.Fatal(err)
	}
	if err := j.MoveStepToDeadLetter(ctx, "run_1", "legacy", "private-legacy-failure", json.RawMessage(`{"value":"legacy"}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed_dlq"); err != nil {
		t.Fatal(err)
	}
	item, err := j.FindDeadLetterByRun(ctx, "run_1")
	if err != nil || item.StepSeq != nil {
		t.Fatalf("nullable keyed DLQ = %+v, %v", item, err)
	}
	if ok, err := j.StartDeadLetterRetryItem(ctx, "run_1", item.ID); err != nil || !ok {
		t.Fatalf("promote keyed legacy DLQ = %v, %v", ok, err)
	}
	promoted, err := j.GetDeadLetterItem(ctx, item.ID)
	if err != nil || promoted.StepSeq == nil || *promoted.StepSeq != 1 ||
		promoted.StepAttempt == nil || *promoted.StepAttempt != 1 ||
		promoted.ErrorText != item.ErrorText || !bytes.Equal(promoted.Payload, item.Payload) {
		t.Fatalf("promoted keyed DLQ = %+v, %v", promoted, err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "repaired", 2, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "repaired", 2, 1, nil, "repair-private-failure"); err != nil {
		t.Fatal(err)
	}
	created, err := j.EnsureStepAttemptDeadLetter(ctx, "run_1", "repaired", 2, 1,
		"repair-private-failure", json.RawMessage(`{"repair":true}`))
	if err != nil || !created {
		t.Fatalf("keyed exact repair = %v, %v", created, err)
	}
	var stored string
	if err := j.db.QueryRowContext(ctx, `SELECT error_text FROM dead_letter WHERE step_name = 'repaired'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "repair-private-failure") {
		t.Fatalf("repair copied plaintext error: %q", stored)
	}
	for _, tc := range []struct {
		step string
		seq  int64
		end  func() error
	}{
		{"atomic", 3, func() error {
			_, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "atomic", 3, 1,
				json.RawMessage(`{"private":"atomic-output"}`), "atomic-private-failure", false)
			return err
		}},
		{"exhausted", 4, func() error {
			return j.FinalizeExhaustedStepAttemptSeq(ctx, "run_1", "exhausted", 4, 1,
				json.RawMessage(`{"private":"exhausted-output"}`), "exhausted-private-failure")
		}},
	} {
		if _, err := j.RecordStepStartSeq(ctx, "run_1", tc.step, tc.seq, 1, "", "h"); err != nil {
			t.Fatal(err)
		}
		if err := tc.end(); err != nil {
			t.Fatalf("%s finalizer = %v", tc.step, err)
		}
		var rawError string
		var rawPayload []byte
		var version int
		if err := j.db.QueryRowContext(ctx, `SELECT error_text, payload, payload_crypto_version
			FROM dead_letter WHERE step_name = ?`, tc.step).Scan(&rawError, &rawPayload, &version); err != nil {
			t.Fatal(err)
		}
		if version != 1 || strings.Contains(rawError, "private-failure") || bytes.Contains(rawPayload, []byte("-output")) {
			t.Fatalf("%s copied plaintext DLQ data: version=%d error=%q payload=%q", tc.step, version, rawError, rawPayload)
		}
	}
}
