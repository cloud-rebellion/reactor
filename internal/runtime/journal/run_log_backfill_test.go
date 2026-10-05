package journal

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestBackfillLegacyRunLogsPreservesExactReadsInBatches(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	legacy := []string{"first private line å界", "second private line"}
	if err := j.SaveRunLogs(ctx, "run_1", legacy); err != nil {
		t.Fatal(err)
	}
	var firstCreated string
	if err := j.db.QueryRowContext(ctx, `SELECT created_at FROM run_logs WHERE run_id = ? AND seq = 0`, "run_1").Scan(&firstCreated); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x45}, 32), nil); err != nil {
		t.Fatal(err)
	}
	var indexSQL string
	if err := j.db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master
		WHERE type = 'index' AND name = 'run_logs_legacy_backfill_idx'`).Scan(&indexSQL); err != nil ||
		!strings.Contains(indexSQL, "payload_crypto_version = 0") {
		t.Fatalf("SQLite legacy backfill partial index = %q, %v", indexSQL, err)
	}
	if err := j.SaveRunLogs(ctx, "run_1", []string{"new encrypted line"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(j.db, EngineSQLite).BackfillLegacyRunLogs(ctx, 1); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed backfill = %v", err)
	}
	for _, limit := range []int{0, maxRunLogBackfillBatch + 1} {
		if _, _, err := j.BackfillLegacyRunLogs(ctx, limit); err == nil {
			t.Fatalf("backfill accepted invalid limit %d", limit)
		}
	}
	converted, more, err := j.BackfillLegacyRunLogs(ctx, 1)
	if err != nil || converted != 1 || !more {
		t.Fatalf("first batch converted=%d more=%t err=%v", converted, more, err)
	}
	var stored, createdAt string
	var version, plainBytes int
	if err := j.db.QueryRowContext(ctx, `SELECT line, payload_crypto_version, plaintext_bytes, created_at
		FROM run_logs WHERE run_id = ? AND seq = 0`, "run_1").Scan(&stored, &version, &plainBytes, &createdAt); err != nil {
		t.Fatal(err)
	}
	if version != 1 || plainBytes != len(legacy[0]) || createdAt != firstCreated ||
		strings.Contains(stored, legacy[0]) || !payloadcrypto.IsByteEnvelope([]byte(stored)) {
		t.Fatalf("first backfilled line was not sealed byte-exactly: version=%d bytes=%d created=%q", version, plainBytes, createdAt)
	}
	if got, err := j.GetRunLogs(ctx, "run_1"); err != nil || len(got) != 3 || got[0] != legacy[0] || got[1] != legacy[1] || got[2] != "new encrypted line" {
		t.Fatalf("mixed log read after first batch = %v, %v", got, err)
	}
	converted, more, err = j.BackfillLegacyRunLogs(ctx, 1)
	if err != nil || converted != 1 || more {
		t.Fatalf("second batch converted=%d more=%t err=%v", converted, more, err)
	}
	converted, more, err = j.BackfillLegacyRunLogs(ctx, 1)
	if err != nil || converted != 0 || more {
		t.Fatalf("idempotent batch converted=%d more=%t err=%v", converted, more, err)
	}
	if got, err := j.GetRunLogs(ctx, "run_1"); err != nil || len(got) != 3 || got[0] != legacy[0] || got[1] != legacy[1] || got[2] != "new encrypted line" {
		t.Fatalf("backfilled log read = %v, %v", got, err)
	}
}

func TestBackfillLegacyRunLogsRejectsOversizedBatchAtomically(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.SaveRunLogs(ctx, "run_1", []string{"first safe line"}); err != nil {
		t.Fatal(err)
	}
	// A historical row can predate the 8 MiB keyed line limit. The backfill
	// must detect its size in SQL without loading it into the process, and it
	// must not commit earlier rows from the same batch.
	if _, err := j.db.ExecContext(ctx, `INSERT INTO run_logs (run_id, seq, line) VALUES (?, ?, ?)`,
		"run_1", 1, strings.Repeat("X", maxRunLogLineBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x46}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.BackfillLegacyRunLogs(ctx, 2); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("oversized legacy line error = %v", err)
	}
	var version int
	if err := j.db.QueryRowContext(ctx, `SELECT payload_crypto_version FROM run_logs WHERE run_id = ? AND seq = 0`, "run_1").Scan(&version); err != nil || version != 0 {
		t.Fatalf("partial backfill committed: version=%d err=%v", version, err)
	}
}
