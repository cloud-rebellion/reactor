package journal

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestPostgresSignalPayloadEnvelopeAndOldWriterCutover(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL signal encryption test")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("signal_payload_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scopedURL := u.String()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), scopedURL); err != nil {
		t.Fatalf("migrate signal schema: %v", err)
	}
	db, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := New(db, EnginePostgres)
	if err := j.CreateWorkflowInTenant(ctx, "wf_signal_pg", "signal-pg", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_signal_pg", "wf_signal_pg", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// An old process starts an unkeyed schedule write before first-key
	// initialization. The gate must make key creation wait for its commit.
	oldTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer oldTx.Rollback()
	if _, err := oldTx.ExecContext(ctx, `INSERT INTO schedules
		(id, run_id, step_name, seq, kind, wake_at, signal_name, signal_token)
		VALUES ('legacy_signal_pg', 'run_signal_pg', 'legacy', 1, 'signal', now() + interval '1 hour', 'approve', 'sig_legacy_pg')`); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x51}, 32)
	keyDone := make(chan error, 1)
	go func() { keyDone <- j.EnablePayloadEncryption(ctx, master, nil) }()
	select {
	case err := <-keyDone:
		t.Fatalf("signal writer did not fence first key initialization: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := oldTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-keyDone; err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schedules
		(id, run_id, step_name, seq, kind, wake_at, signal_name, signal_token)
		VALUES ('late_old_signal_pg', 'run_signal_pg', 'late', 3, 'signal', now() + interval '1 hour', 'approve', 'sig_late_pg')`); err == nil || !strings.Contains(err.Error(), "encrypted signal required") {
		t.Fatalf("old PostgreSQL signal insert bypassed key gate: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schedules SET signal_payload='"old"'::bytea
		WHERE id='legacy_signal_pg'`); err == nil || !strings.Contains(err.Error(), "encrypted signal required") {
		t.Fatalf("old PostgreSQL signal delivery bypassed key gate: %v", err)
	}
	const token = "sig_private_pg"
	const delivered = `{"secret":"postgres-signal-only"}`
	if _, err := j.ScheduleSignalSeq(ctx, "run_signal_pg", "approval", 2, "approve", token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.FireSignalForTenant(ctx, "foreign", token, []byte(delivered)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant delivery = %v", err)
	}
	if _, _, err := j.FireSignalForTenant(ctx, "acme", token, []byte(delivered)); err != nil {
		t.Fatal(err)
	}
	var plain sql.NullString
	var cipher, digest string
	var stored []byte
	var version int
	if err := db.QueryRowContext(ctx, `SELECT signal_token, signal_token_ciphertext,
		signal_token_sha256, signal_payload, signal_crypto_version FROM schedules
		WHERE run_id='run_signal_pg' AND seq=2`).Scan(&plain, &cipher, &digest, &stored, &version); err != nil {
		t.Fatal(err)
	}
	if plain.Valid || strings.Contains(cipher, token) || !payloadcrypto.IsByteEnvelope([]byte(cipher)) ||
		digest != signalTokenDigest(token) || bytes.Contains(stored, []byte("postgres-signal-only")) ||
		!payloadcrypto.IsByteEnvelope(stored) || version != 1 {
		t.Fatalf("unsafe PostgreSQL signal storage: plain=%v cipher=%q hash=%q payload=%q version=%d",
			plain.Valid, cipher, digest, stored, version)
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_signal_pg", 2, KindSignal); err != nil ||
		got.SignalToken != token || string(got.SignalPayload) != delivered {
		t.Fatalf("PostgreSQL signal replay = %+v, %v", got, err)
	}
	if _, _, err := j.FireSignal(ctx, "sig_legacy_pg", []byte(`"promoted"`)); err != nil {
		t.Fatal(err)
	}
	if got, err := j.FindScheduleBySeq(ctx, "run_signal_pg", 1, KindSignal); err != nil ||
		got.SignalToken != "sig_legacy_pg" || string(got.SignalPayload) != `"promoted"` {
		t.Fatalf("PostgreSQL legacy promotion = %+v, %v", got, err)
	}
	if err := j.SetRunStatus(ctx, "run_signal_pg", "suspended"); err != nil {
		t.Fatal(err)
	}
	if due, err := j.FindDueSchedules(ctx, time.Now().Add(time.Second), 10); err != nil || len(due) != 2 {
		t.Fatalf("PostgreSQL due encrypted signals = %+v, %v", due, err)
	}
	unkeyed := New(db, EnginePostgres)
	if _, err := unkeyed.FindScheduleBySeq(ctx, "run_signal_pg", 2, KindSignal); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed PostgreSQL signal replay = %v", err)
	}
}
