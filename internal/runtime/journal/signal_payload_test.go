package journal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestSignalTokenAndDeliveryEncryptedAtRestAndReplay(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	master := bytes.Repeat([]byte{0x6b}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	const token = "sig_synthetic_private_capability"
	const payload = `{"private":"synthetic-signal-payload"}`
	id, err := j.ScheduleSignalSeq(ctx, "run_1", "approval", 1, "approve", token, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var plain sql.NullString
	var cipher, digest string
	var storedPayload []byte
	var version, tokenBytes int
	if err := j.db.QueryRowContext(ctx, `SELECT signal_token, signal_token_ciphertext, signal_token_sha256,
		signal_payload, signal_crypto_version, signal_token_plaintext_bytes
		FROM schedules WHERE id = ?`, id).Scan(&plain, &cipher, &digest, &storedPayload, &version, &tokenBytes); err != nil {
		t.Fatal(err)
	}
	if plain.Valid || strings.Contains(cipher, token) || !payloadcrypto.IsByteEnvelope([]byte(cipher)) ||
		digest != signalTokenDigest(token) || storedPayload != nil || version != 1 || tokenBytes != len(token) {
		t.Fatalf("unsafe pending signal storage: plain=%v cipher=%q digest=%q payload=%q version=%d bytes=%d",
			plain.Valid, cipher, digest, storedPayload, version, tokenBytes)
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal); err != nil || got.SignalToken != token || len(got.SignalPayload) != 0 {
		t.Fatalf("pending replay = %+v, %v", got, err)
	}
	if runID, signalName, err := j.FireSignal(ctx, token, []byte(payload)); err != nil || runID != "run_1" || signalName != "approve" {
		t.Fatalf("signal delivery = %q/%q, %v", runID, signalName, err)
	}
	var payloadBytes int
	if err := j.db.QueryRowContext(ctx, `SELECT signal_payload, signal_payload_plaintext_bytes
		FROM schedules WHERE id = ?`, id).Scan(&storedPayload, &payloadBytes); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedPayload, []byte("synthetic-signal-payload")) ||
		!payloadcrypto.IsByteEnvelope(storedPayload) || payloadBytes != len(payload) {
		t.Fatalf("unsafe delivered signal storage: payload=%q bytes=%d", storedPayload, payloadBytes)
	}
	got, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal)
	if err != nil || got.SignalToken != token || !bytes.Equal(got.SignalPayload, []byte(payload)) {
		t.Fatalf("delivered replay = %+v, %v", got, err)
	}
	page, more, err := j.ListPendingSchedulesForRunTenantPageMetadata(ctx, "run_1", DefaultTenant, 10, 0)
	if err != nil || more || len(page) != 1 || !page[0].SignalTokenPresent || !page[0].SignalPayloadPresent ||
		page[0].SignalToken != "" || len(page[0].SignalPayload) != 0 {
		t.Fatalf("metadata projection = %+v more=%v err=%v", page, more, err)
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.FindScheduleBySeq(ctx, "run_1", 1, KindSignal); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed replay = %v", err)
	}
	if _, err := unkeyed.ScheduleSignalSeq(ctx, "run_1", "late", 2, "approve", "sig_late", time.Now().Add(time.Hour)); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed schedule write = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO schedules
		(id, run_id, step_name, seq, kind, wake_at, signal_name, signal_token)
		VALUES ('old_binary_signal', 'run_1', 'late', 3, 'signal', ?, 'approve', 'sig_old_binary')`,
		j.formatTime(time.Now().Add(time.Hour))); err == nil || !strings.Contains(err.Error(), "encrypted signal required") {
		t.Fatalf("old binary signal insert escaped key fence: %v", err)
	}
}

func TestLegacyPendingSignalPromotesAtomicallyOnDelivery(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const token = "sig_legacy_pending"
	id, err := j.ScheduleSignalSeq(ctx, "run_1", "legacy", 1, "approve", token, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x74}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSignalSeq(ctx, "run_1", "legacy", 2, "approve", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE schedules SET signal_payload = '"old-writer"'
		WHERE id = ?`, id); err == nil || !strings.Contains(err.Error(), "encrypted signal required") {
		t.Fatalf("old binary delivery escaped key fence: %v", err)
	}
	if _, _, err := j.FireSignal(ctx, token, []byte(`"new-delivery"`)); err != nil {
		t.Fatal(err)
	}
	var plain sql.NullString
	var cipher, digest string
	var version int
	if err := j.db.QueryRowContext(ctx, `SELECT signal_token, signal_token_ciphertext,
		signal_token_sha256, signal_crypto_version FROM schedules WHERE id = ?`, id).
		Scan(&plain, &cipher, &digest, &version); err != nil {
		t.Fatal(err)
	}
	if plain.Valid || !payloadcrypto.IsByteEnvelope([]byte(cipher)) || digest != signalTokenDigest(token) || version != 1 {
		t.Fatalf("legacy row was not promoted: plain=%v cipher=%q hash=%q version=%d", plain, cipher, digest, version)
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal); err != nil ||
		got.SignalToken != token || string(got.SignalPayload) != `"new-delivery"` {
		t.Fatalf("promoted replay = %+v, %v", got, err)
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal); err != nil || len(got.SignalPayload) != 0 {
		t.Fatalf("second await consumed first delivery = %+v, %v", got, err)
	}
	if _, _, err := j.FireSignal(ctx, token, []byte(`"second-delivery"`)); err != nil {
		t.Fatal(err)
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal); err != nil ||
		string(got.SignalPayload) != `"second-delivery"` {
		t.Fatalf("second await after cutover = %+v, %v", got, err)
	}
}

func TestSignalCiphertextCannotCrossOrdinal(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x5e}, 32), nil); err != nil {
		t.Fatal(err)
	}
	const token = "sig_same_name"
	for seq := int64(1); seq <= 2; seq++ {
		if _, err := j.ScheduleSignalSeq(ctx, "run_1", "approval", seq, "approve", token, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := j.FireSignal(ctx, token, []byte(`"accepted"`)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal)
	if err != nil {
		t.Fatal(err)
	}
	second, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE schedules SET signal_payload =
		(SELECT signal_payload FROM schedules WHERE id = ?) WHERE id = ?`, second.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("cross-ordinal payload swap authenticated: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE schedules SET signal_token_ciphertext =
		(SELECT signal_token_ciphertext FROM schedules WHERE id = ?) WHERE id = ?`, first.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("cross-ordinal token swap authenticated: %v", err)
	}
}

func TestEncryptedSignalDeliveryHonorsWireSizeBoundary(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x67}, 32), nil); err != nil {
		t.Fatal(err)
	}
	prefix, suffix := []byte(`{"v":"`), []byte(`"}`)
	payload := append(append(append([]byte(nil), prefix...),
		bytes.Repeat([]byte{'a'}, maxSignalPayloadBytes-len(prefix)-len(suffix))...), suffix...)
	if len(payload) != maxSignalPayloadBytes {
		t.Fatalf("boundary fixture has %d bytes", len(payload))
	}
	if _, err := j.ScheduleSignalSeq(ctx, "run_1", "max", 1, "max", "sig_max_encrypted", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.FireSignal(ctx, "sig_max_encrypted", payload); err != nil {
		t.Fatalf("wire-limit encrypted delivery: %v", err)
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_1", 1, KindSignal); err != nil || !bytes.Equal(got.SignalPayload, payload) {
		t.Fatalf("wire-limit replay bytes=%d err=%v", len(got.SignalPayload), err)
	}
	if _, err := j.ScheduleSignalSeq(ctx, "run_1", "over", 2, "over", "sig_over_encrypted", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.FireSignal(ctx, "sig_over_encrypted", append(payload, ' ')); err == nil {
		t.Fatal("oversized encrypted delivery was accepted")
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_1", 2, KindSignal); err != nil || len(got.SignalPayload) != 0 {
		t.Fatalf("oversized delivery mutated pending await = %+v, %v", got, err)
	}
}
