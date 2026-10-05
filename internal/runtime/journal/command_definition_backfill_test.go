package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestBackfillLegacyCommandDefinitionsPreservesExactReadsAndReviewDigest(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"printf legacy-private-command","purpose":"Check","timeout_seconds":30}]}`)
	a, err := j.CreateCommandAutomation(ctx, "acme", "cmd_backfill_a", "backfill-a", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandAutomation(ctx, "acme", "cmd_backfill_b", "backfill-b", "", "local", "alice", definition); err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, definition, "", "  "); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_automation_versions SET definition_json = ? WHERE automation_id = ? AND version = 1`,
		indented.String(), a.ID); err != nil {
		t.Fatal(err)
	}
	before, err := j.GetCommandAutomationVersion(ctx, "acme", a.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	beforeSummary, _, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", a.ID, 1, 0)
	if err != nil || len(beforeSummary) != 1 {
		t.Fatalf("legacy summary = %+v, %v", beforeSummary, err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x76}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(j.db, EngineSQLite).BackfillLegacyCommandDefinitions(ctx, 1); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("unkeyed backfill = %v", err)
	}
	if _, _, err := j.BackfillLegacyCommandDefinitions(ctx, 33); err == nil {
		t.Fatal("oversized backfill batch accepted")
	}
	converted, more, err := j.BackfillLegacyCommandDefinitions(ctx, 1)
	if err != nil || converted != 1 || !more {
		t.Fatalf("first batch converted=%d more=%v err=%v", converted, more, err)
	}
	var stored string
	var cryptoVersion, plainBytes int
	var rawDigest, canonicalDigest string
	if err := j.db.QueryRowContext(ctx, `SELECT definition_json, definition_crypto_version,
		definition_plaintext_bytes, definition_sha256, definition_canonical_sha256
		FROM command_automation_versions WHERE automation_id = ? AND version = 1`, a.ID).
		Scan(&stored, &cryptoVersion, &plainBytes, &rawDigest, &canonicalDigest); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(before.DefinitionJSON)
	if cryptoVersion != 1 || plainBytes != len(before.DefinitionJSON) ||
		rawDigest != hex.EncodeToString(sum[:]) || canonicalDigest != beforeSummary[0].DefinitionSHA256 ||
		strings.Contains(stored, "legacy-private-command") {
		t.Fatalf("backfilled storage metadata is wrong: version=%d bytes=%d raw=%q canonical=%q", cryptoVersion, plainBytes, rawDigest, canonicalDigest)
	}
	after, err := j.GetCommandAutomationVersion(ctx, "acme", a.ID, 1)
	if err != nil || !bytes.Equal(after.DefinitionJSON, before.DefinitionJSON) {
		t.Fatalf("exact definition changed after backfill: err=%v", err)
	}
	afterSummary, _, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", a.ID, 1, 0)
	if err != nil || len(afterSummary) != 1 || afterSummary[0].DefinitionSHA256 != beforeSummary[0].DefinitionSHA256 {
		t.Fatalf("review digest changed after backfill: %+v, %v", afterSummary, err)
	}
	converted, more, err = j.BackfillLegacyCommandDefinitions(ctx, 1)
	if err != nil || converted != 1 || more {
		t.Fatalf("second batch converted=%d more=%v err=%v", converted, more, err)
	}
	converted, more, err = j.BackfillLegacyCommandDefinitions(ctx, 1)
	if err != nil || converted != 0 || more {
		t.Fatalf("idempotent batch converted=%d more=%v err=%v", converted, more, err)
	}
}

func TestBackfillLegacyCommandDefinitionsRejectsCorruptBatchAtomically(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_backfill_corrupt", "backfill-corrupt", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO command_automation_versions (automation_id, version, definition_json)
		VALUES (?, 2, ?)`, plan.ID, `{broken`); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x77}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.BackfillLegacyCommandDefinitions(ctx, 32); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("corrupt batch = %v", err)
	}
	var version int
	if err := j.db.QueryRowContext(ctx, `SELECT definition_crypto_version FROM command_automation_versions
		WHERE automation_id = ? AND version = 1`, plan.ID).Scan(&version); err != nil || version != 0 {
		t.Fatalf("partial backfill committed: version=%d err=%v", version, err)
	}
}
