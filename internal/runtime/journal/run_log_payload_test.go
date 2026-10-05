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

func TestRunLogsEncryptedAfterKeyAndAuthenticatedOnRead(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const secret = "synthetic-log-private-å界"
	if err := j.SaveRunLogs(ctx, "run_1", []string{"legacy-before-key"}); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x46}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if err := j.SaveRunLogs(ctx, "run_1", []string{secret}); err != nil {
		t.Fatal(err)
	}
	if err := j.SaveRunLogs(ctx, "run_1", []string{secret}); err != nil {
		t.Fatalf("idempotent encrypted flush: %v", err)
	}
	var stored string
	var version, plainBytes int
	if err := j.db.QueryRowContext(ctx, `SELECT line, payload_crypto_version, plaintext_bytes
		FROM run_logs WHERE run_id = ? AND seq = 1`, "run_1").Scan(&stored, &version, &plainBytes); err != nil {
		t.Fatal(err)
	}
	if version != 1 || plainBytes != len(secret) || strings.Contains(stored, secret) ||
		!payloadcrypto.IsByteEnvelope([]byte(stored)) {
		t.Fatalf("unsafe durable log: version=%d plainBytes=%d envelope=%t secretOnDisk=%t",
			version, plainBytes, payloadcrypto.IsByteEnvelope([]byte(stored)), strings.Contains(stored, secret))
	}
	var count int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM run_logs WHERE run_id = ?`, "run_1").Scan(&count); err != nil || count != 2 {
		t.Fatalf("duplicate durable logs: count=%d err=%v", count, err)
	}
	logs, err := j.GetRunLogs(ctx, "run_1")
	if err != nil || len(logs) != 2 || logs[0] != "legacy-before-key" || logs[1] != secret {
		t.Fatalf("legacy and encrypted read = %v, %v", logs, err)
	}
	page, err := j.GetRunLogsPageForTenantBounded(ctx, "run_1", DefaultTenant, 1, 1, len(secret)-1)
	if err != nil || len(page) != 1 || page[0].Text != "" || page[0].Bytes != len(secret) || !page[0].Truncated {
		t.Fatalf("bounded encrypted read = %+v, %v", page, err)
	}
	page, err = j.GetRunLogsPageForTenantBounded(ctx, "run_1", DefaultTenant, 1, 1, len(secret))
	if err != nil || len(page) != 1 || page[0].Text != secret || page[0].Truncated {
		t.Fatalf("exact bounded encrypted read = %+v, %v", page, err)
	}
	if foreign, err := j.GetRunLogsPageForTenant(ctx, "run_1", "other", 10, 0); err != nil || len(foreign) != 0 {
		t.Fatalf("foreign tenant read = %v, %v", foreign, err)
	}
	restarted := New(j.db, EngineSQLite)
	if err := restarted.LoadPayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	if replay, err := restarted.GetRunLogs(ctx, "run_1"); err != nil || len(replay) != 2 || replay[1] != secret {
		t.Fatalf("restarted replay = %v, %v", replay, err)
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.GetRunLogs(ctx, "run_1"); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed log read = %v", err)
	}
	if err := unkeyed.SaveRunLogs(ctx, "run_1", []string{"unsafe"}); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed log write = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO run_logs (run_id, seq, line) VALUES (?, ?, ?)`,
		"run_1", 2, "old-binary-plaintext"); err == nil || !strings.Contains(err.Error(), "encrypted run log required") {
		t.Fatalf("old writer bypassed run-log guard: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE run_logs SET payload_crypto_version = 0, plaintext_bytes = NULL, line = ?
		WHERE run_id = ? AND seq = 1`, "downgraded", "run_1"); err == nil {
		t.Fatal("encrypted run log downgraded to plaintext")
	}
	if err := j.SaveRunLogs(ctx, "run_1", []string{"retry-tail"}); err != nil {
		t.Fatal(err)
	}
	if got, err := j.GetRunLogs(ctx, "run_1"); err != nil || len(got) != 3 || got[2] != "retry-tail" {
		t.Fatalf("retry logs = %v, %v", got, err)
	}
	var otherEnvelope string
	if err := j.db.QueryRowContext(ctx, `SELECT line FROM run_logs WHERE run_id = ? AND seq = 2`, "run_1").Scan(&otherEnvelope); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE run_logs SET line = ? WHERE run_id = ? AND seq = 1`,
		otherEnvelope, "run_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetRunLogs(ctx, "run_1"); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered encrypted log = %v", err)
	}
}

func TestEncryptedArtifactFenceLogKeepsDeduplication(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x72}, 32), nil); err != nil {
		t.Fatal(err)
	}
	scheduleID, err := j.ScheduleSleep(ctx, "run_1", "wait", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		deferred, err := j.DeferScheduleArtifactAvailability(ctx, scheduleID, "run_1", time.Now().Add(time.Minute))
		if err != nil || !deferred {
			t.Fatalf("artifact deferral %d = %v, %v", i, deferred, err)
		}
	}
	var stored, kind string
	var version int
	var plainBytes sql.NullInt64
	if err := j.db.QueryRowContext(ctx, `SELECT line, kind, payload_crypto_version, plaintext_bytes
		FROM run_logs WHERE run_id = ?`, "run_1").Scan(&stored, &kind, &version, &plainBytes); err != nil {
		t.Fatal(err)
	}
	if kind != runLogKindArtifactFence || version != 1 || !plainBytes.Valid ||
		plainBytes.Int64 != int64(len(WorkflowArtifactFenceRunLog)) ||
		strings.Contains(stored, WorkflowArtifactFenceRunLog) {
		t.Fatalf("artifact marker at rest: kind=%q version=%d bytes=%v plaintext=%t",
			kind, version, plainBytes, strings.Contains(stored, WorkflowArtifactFenceRunLog))
	}
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM run_logs WHERE run_id = ?`, "run_1").Scan(&version); err != nil || version != 1 {
		t.Fatalf("artifact deferral duplicate marker: count=%d err=%v", version, err)
	}
	if logs, err := j.GetRunLogs(ctx, "run_1"); err != nil || len(logs) != 1 || logs[0] != WorkflowArtifactFenceRunLog {
		t.Fatalf("artifact marker read = %v, %v", logs, err)
	}
}

func TestOversizedHistoricalRunLogDoesNotBlockNewEncryptedFlush(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	legacy := strings.Repeat("L", maxRunLogLineBytes+1)
	if _, err := j.db.ExecContext(ctx, `INSERT INTO run_logs (run_id, seq, line) VALUES (?, ?, ?)`,
		"run_1", 0, legacy); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x31}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if err := j.SaveRunLogs(ctx, "run_1", []string{"new encrypted line"}); err != nil {
		t.Fatalf("oversized historical tail blocked a new flush: %v", err)
	}
	page, err := j.GetRunLogsPageForTenantBounded(ctx, "run_1", DefaultTenant, 1, 0, 32)
	if err != nil || len(page) != 1 || page[0].Bytes != len(legacy) || !page[0].Truncated || page[0].Text != "" {
		t.Fatalf("oversized legacy bounded view = %+v, %v", page, err)
	}
	if _, err := j.GetRunLogs(ctx, "run_1"); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("unbounded read materialized oversized legacy line: %v", err)
	}
	if newer, err := j.GetRunLogsPage(ctx, "run_1", 1, 1); err != nil || len(newer) != 1 || newer[0] != "new encrypted line" {
		t.Fatalf("new line after oversized legacy tail = %v, %v", newer, err)
	}
}
