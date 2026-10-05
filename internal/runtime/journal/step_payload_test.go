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

func TestStepPayloadEncryptedAtRestReplayAndBoundedViews(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const runID, stepName = "run_step_crypto", "repeat"
	if err := j.CreateWorkflowInTenant(ctx, "wf_step_crypto", "step-crypto", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	keyA := bytes.Repeat([]byte{0x31}, 32)
	keyB := bytes.Repeat([]byte{0x42}, 32)
	if err := j.EnablePayloadEncryption(ctx, keyA, nil); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, runID, "wf_step_crypto", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	output := json.RawMessage(` { "private": "synthetic-step-secret", "n": 1 } `)
	if _, err := j.RecordStepStartSeq(ctx, runID, stepName, 1, 1, "idem", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, runID, stepName, 1, 1, output, ""); err != nil {
		t.Fatal(err)
	}
	var storedOutput []byte
	var storedError sql.NullString
	var version int
	var outputLen, errorLen sql.NullInt64
	if err := j.db.QueryRowContext(ctx, `SELECT output_jsonb, error_text, payload_crypto_version,
		output_plaintext_bytes, error_plaintext_bytes FROM steps WHERE run_id = ? AND seq = 1`, runID).
		Scan(&storedOutput, &storedError, &version, &outputLen, &errorLen); err != nil {
		t.Fatal(err)
	}
	if version != 1 || !outputLen.Valid || outputLen.Int64 != int64(len(output)) || storedError.Valid || errorLen.Valid ||
		bytes.Contains(storedOutput, []byte("synthetic-step-secret")) {
		t.Fatalf("unsafe step row: version=%d output=%q error=%v lengths=%v/%v", version, storedOutput, storedError, outputLen, errorLen)
	}
	got, recorded, idem, inputHash, err := j.FindCachedOutputBySeqForInput(ctx, runID, 1)
	if err != nil || !bytes.Equal(got, output) || recorded != stepName || idem != "idem" || inputHash != "hash" {
		t.Fatalf("replay = %q / %s / %s / %s, %v", got, recorded, idem, inputHash, err)
	}
	got, err = j.FindCachedOutputForInput(ctx, runID, stepName, "idem", "hash")
	if err != nil || !bytes.Equal(got, output) {
		t.Fatalf("name/input cache = %q, %v", got, err)
	}
	steps, err := j.ListStepsPageForTenantBounded(ctx, runID, "acme", 10, 0, len(output), 64)
	if err != nil || len(steps) != 1 || !bytes.Equal(steps[0].OutputJSONB, output) {
		t.Fatalf("bounded step view = %+v, %v", steps, err)
	}
	steps, err = j.ListStepsPageForTenantBounded(ctx, runID, "acme", 10, 0, len(output)-1, 0)
	if err != nil || len(steps) != 1 || len(steps[0].OutputJSONB) != 0 ||
		!steps[0].OutputTruncated || steps[0].OutputBytes != len(output) {
		t.Fatalf("redacted step view = %+v, %v", steps, err)
	}
	if steps, err := j.ListStepsPageForTenantBounded(ctx, runID, "foreign", 10, 0, 64, 64); err != nil || len(steps) != 0 {
		t.Fatalf("foreign tenant step view = %+v, %v", steps, err)
	}
	page, chars, err := j.ReadStepOutputPageForTenant(ctx, runID, "acme", stepName, 1, 1, 2, 7)
	if err != nil || chars != len([]rune(string(output))) || string(page.OutputJSONB) != string([]rune(string(output))[2:9]) {
		t.Fatalf("authenticated output page = %q / %d, %v", page.OutputJSONB, chars, err)
	}
	if _, _, err := j.ReadStepOutputPageForTenant(ctx, runID, "foreign", stepName, 1, 1, 0, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign exact page = %v", err)
	}
	latest, err := j.LatestSuccessfulStepOutputBounded(ctx, runID, stepName, len(output))
	if err != nil || !bytes.Equal(latest.OutputJSONB, output) {
		t.Fatalf("latest output = %+v, %v", latest, err)
	}
	if _, _, err := New(j.db, EngineSQLite).FindCachedOutputBySeq(ctx, runID, 1); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed replay = %v", err)
	}
	rotated := New(j.db, EngineSQLite)
	if err := rotated.EnablePayloadEncryption(ctx, keyB, keyA); err != nil {
		t.Fatal(err)
	}
	if got, _, err := rotated.FindCachedOutputBySeq(ctx, runID, 1); err != nil || !bytes.Equal(got, output) {
		t.Fatalf("post-rotation replay = %q, %v", got, err)
	}
}

func TestStepPayloadErrorAndTamperFailClosed(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x53}, 32), nil); err != nil {
		t.Fatal(err)
	}
	const errorText = "synthetic-step-error-private"
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "failed", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "failed", 1, 1, nil, errorText); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := j.db.QueryRowContext(ctx, `SELECT error_text FROM steps WHERE run_id = ? AND seq = 1`, "run_1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, errorText) || !payloadcrypto.IsByteEnvelope([]byte(raw)) {
		t.Fatalf("plaintext step error persisted: %q", raw)
	}
	state, err := j.LatestStepAttemptSeq(ctx, "run_1", "failed", 1)
	if err != nil || state.ErrorText != errorText {
		t.Fatalf("durable error state = %+v, %v", state, err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed"); err != nil {
		t.Fatal(err)
	}
	event, err := j.GetTerminalEffectEvent(ctx, "run_1")
	if err != nil || event.ErrorText != errorText {
		t.Fatalf("terminal event = %+v, %v", event, err)
	}
	failed, err := j.ListFailedRuns(ctx, "default", 10)
	if err != nil || len(failed) != 1 || failed[0].Error != errorText {
		t.Fatalf("failure view = %+v, %v", failed, err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE steps SET error_text = ? WHERE run_id = ? AND seq = 1`, "tampered", "run_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.LatestStepAttemptSeq(ctx, "run_1", "failed", 1); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered state = %v", err)
	}
	if _, err := j.GetTerminalEffectEvent(ctx, "run_1"); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered terminal error = %v", err)
	}
	if _, err := j.ListFailedRuns(ctx, "default", 10); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered failure view = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE steps SET payload_crypto_version = 0 WHERE run_id = ? AND seq = 1`, "run_1"); err == nil {
		t.Fatal("encrypted step version downgraded")
	}
}

func TestStepPayloadOldWriterAndSwappedOutputFence(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "legacy", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "legacy", 1, 1, json.RawMessage(`{"old":true}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x64}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if got, _, err := j.FindCachedOutputBySeq(ctx, "run_1", 1); err != nil || string(got) != `{"old":true}` {
		t.Fatalf("historical v0 replay = %q, %v", got, err)
	}
	for _, seq := range []int64{2, 3} {
		if _, err := j.RecordStepStartSeq(ctx, "run_1", "repeat", seq, 1, "", "h"); err != nil {
			t.Fatal(err)
		}
		if err := j.RecordStepEndSeq(ctx, "run_1", "repeat", seq, 1,
			json.RawMessage(`{"seq":`+string(rune('0'+seq))+`}`), ""); err != nil {
			t.Fatal(err)
		}
	}
	var a, b []byte
	if err := j.db.QueryRowContext(ctx, `SELECT output_jsonb FROM steps WHERE run_id = ? AND seq = 2`, "run_1").Scan(&a); err != nil {
		t.Fatal(err)
	}
	if err := j.db.QueryRowContext(ctx, `SELECT output_jsonb FROM steps WHERE run_id = ? AND seq = 3`, "run_1").Scan(&b); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE steps SET output_jsonb = CASE seq WHEN 2 THEN ? ELSE ? END
		WHERE run_id = ? AND seq IN (2,3)`, string(b), string(a), "run_1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.FindCachedOutputBySeq(ctx, "run_1", 2); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("swapped attempt replay = %v", err)
	}
	if _, _, err := j.ReadStepOutputPage(ctx, "run_1", "repeat", 2, 1, 0, 10); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("swapped audited page = %v", err)
	}
	// A forged oversized v1 envelope must be rejected by the SQL projection
	// before a replay, historical list, or audited page materializes it.
	oversized := `{"__reactor_payload_envelope":"` + strings.Repeat("x", payloadcrypto.JSONCiphertextLimit(maxStepPayloadPlaintextBytes)+1) + `"}`
	if _, err := j.db.ExecContext(ctx, `UPDATE steps SET output_jsonb = ? WHERE run_id = ? AND seq = 2`, oversized, "run_1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.FindCachedOutputBySeq(ctx, "run_1", 2); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("oversized cached read = %v", err)
	}
	if _, err := j.LatestStepAttemptSeq(ctx, "run_1", "repeat", 2); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("oversized attempt read = %v", err)
	}
	if _, err := j.ListStepsPage(ctx, "run_1", 10, 0); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("oversized historical list = %v", err)
	}
	if _, _, err := j.ReadStepOutputPage(ctx, "run_1", "repeat", 2, 1, 0, 10); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("oversized audited page = %v", err)
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.RecordStepStartSeq(ctx, "run_1", "old-writer", 4, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	if err := unkeyed.RecordStepEndSeq(ctx, "run_1", "old-writer", 4, 1, json.RawMessage(`{"secret":"no"}`), ""); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed writer = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE steps SET output_jsonb = ? WHERE run_id = ? AND seq = 4`,
		`{"secret":"old binary"}`, "run_1"); err == nil || !strings.Contains(err.Error(), "encrypted step required") {
		t.Fatalf("old binary bypassed DB fence: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO steps
		(run_id, step_name, seq, attempt, input_hash, status, started_at, output_jsonb)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "run_1", "direct-insert", 5, 1, "h", "succeeded", j.now(), `{"secret":"old binary"}`); err == nil || !strings.Contains(err.Error(), "encrypted step required") {
		t.Fatalf("old binary direct INSERT bypassed DB fence: %v", err)
	}
}

func TestStepPayloadAllFinalizersSealStepColumns(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x76}, 32), nil); err != nil {
		t.Fatal(err)
	}
	const private = "synthetic-finalizer-secret"
	for _, tc := range []struct {
		name string
		seq  int64
		end  func() error
	}{
		{"with-retry", 1, func() error {
			return j.RecordStepEndWithRetrySeq(ctx, "run_1", "with-retry", 1, 1, nil, private, true)
		}},
		{"atomic-finalize", 2, func() error {
			_, err := j.FinalizeStepAttemptSeq(ctx, "run_1", "atomic-finalize", 2, 1,
				json.RawMessage(`{"private":"`+private+`"}`), "", false)
			return err
		}},
		{"exhausted", 3, func() error {
			return j.FinalizeExhaustedStepAttemptSeq(ctx, "run_1", "exhausted", 3, 1, nil, private)
		}},
	} {
		if _, err := j.RecordStepStartSeq(ctx, "run_1", tc.name, tc.seq, 1, "", "h"); err != nil {
			t.Fatal(err)
		}
		if err := tc.end(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var output []byte
		var errorText sql.NullString
		var version int
		if err := j.db.QueryRowContext(ctx, `SELECT output_jsonb, error_text, payload_crypto_version
			FROM steps WHERE run_id = ? AND seq = ?`, "run_1", tc.seq).Scan(&output, &errorText, &version); err != nil {
			t.Fatal(err)
		}
		if version != 1 || bytes.Contains(output, []byte(private)) || strings.Contains(errorText.String, private) {
			t.Fatalf("%s persisted plaintext: version=%d output=%q error=%q", tc.name, version, output, errorText.String)
		}
		if state, err := j.LatestStepAttemptSeq(ctx, "run_1", tc.name, tc.seq); err != nil ||
			!strings.Contains(string(state.Output)+state.ErrorText, private) {
			t.Fatalf("%s replay = %+v, %v", tc.name, state, err)
		}
	}
}
