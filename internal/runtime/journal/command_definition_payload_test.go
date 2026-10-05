package journal

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/payloadcrypto"
)

func TestCommandDefinitionEnvelopeReadBindingsAndOldWriterFence(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"printf synthetic-private-command","purpose":"Check private output","timeout_seconds":30}]}`)
	_, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := j.CreateCommandAutomation(ctx, "acme", "cmd_def_legacy", "def-legacy", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	commandWebhookCredential(t, j, "cred_cmd_def_crypto", "acme")
	if err := j.CreateWorkflowInTenant(ctx, "wf_def_crypto_source", "def-crypto-source", "h", "0.1.0", []byte(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x70}, 32)
	if err := j.EnablePayloadEncryption(ctx, master, nil); err != nil {
		t.Fatal(err)
	}
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_def_crypto", "def-crypto", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if next, err := j.AppendCommandAutomationVersion(ctx, "acme", plan.ID, "bob", 1, definition); err != nil || next != 2 {
		t.Fatalf("keyed append = %d, %v", next, err)
	}
	plan.CurrentVersion = 2
	var storedV1, storedV2 []byte
	var version, plainBytes int
	var digest string
	if err := j.db.QueryRowContext(ctx, `SELECT definition_json, definition_crypto_version, definition_plaintext_bytes, definition_sha256
		FROM command_automation_versions WHERE automation_id = ? AND version = 1`, plan.ID).Scan(&storedV1, &version, &plainBytes, &digest); err != nil {
		t.Fatal(err)
	}
	if version != 1 || plainBytes != len(normalized) || digest != commandDefinitionDigest(t, definition) ||
		bytes.Contains(storedV1, []byte("synthetic-private-command")) || !bytes.Contains(storedV1, []byte("__reactor_payload_envelope")) {
		t.Fatalf("unsafe keyed definition: version=%d bytes=%d digest=%q stored=%s", version, plainBytes, digest, storedV1)
	}
	if err := j.db.QueryRowContext(ctx, `SELECT definition_json FROM command_automation_versions WHERE automation_id = ? AND version = 2`, plan.ID).Scan(&storedV2); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(storedV1, storedV2) || bytes.Contains(storedV2, []byte("synthetic-private-command")) {
		t.Fatal("distinct keyed versions reused or exposed plaintext")
	}
	for _, v := range []int{1, 2} {
		got, err := j.GetCommandAutomationVersion(ctx, "acme", plan.ID, v)
		if err != nil || !bytes.Equal(got.DefinitionJSON, normalized) {
			t.Fatalf("exact keyed version %d = %+v, %v", v, got, err)
		}
	}
	if _, err := j.GetCommandAutomationVersion(ctx, "other", plan.ID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant exact version = %v", err)
	}
	legacyVersion, err := j.GetCommandAutomationVersion(ctx, "acme", legacy.ID, 1)
	if err != nil || !bytes.Equal(legacyVersion.DefinitionJSON, normalized) {
		t.Fatalf("historical v0 definition = %+v, %v", legacyVersion, err)
	}
	page, more, err := j.ListCommandAutomationVersionsPage(ctx, "acme", plan.ID, 2, 0)
	if err != nil || more || len(page) != 2 || !bytes.Equal(page[0].DefinitionJSON, normalized) || !bytes.Equal(page[1].DefinitionJSON, normalized) {
		t.Fatalf("keyed export page = %+v more=%v err=%v", page, more, err)
	}
	all, err := j.ListCommandAutomationVersions(ctx, "acme", plan.ID)
	if err != nil || len(all) != 2 {
		t.Fatalf("keyed export list = %+v, %v", all, err)
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.GetCommandAutomationVersion(ctx, "acme", plan.ID, 1); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("keyless exact read = %v", err)
	}
	if _, err := unkeyed.CreateCommandAutomation(ctx, "acme", "cmd_def_unkeyed", "def-unkeyed", "", "local", "alice", definition); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("keyless create = %v", err)
	}
	if _, err := unkeyed.AppendCommandAutomationVersion(ctx, "acme", legacy.ID, "mallory", 1, definition); !errors.Is(err, payloadcrypto.ErrKeyRequired) {
		t.Fatalf("keyless append = %v", err)
	}
	index, more, err := unkeyed.ListCommandAutomationVersionSummariesPage(ctx, "acme", plan.ID, 2, 0)
	if err != nil || more || len(index) != 2 || index[0].DefinitionSHA256 != digest || index[0].DefinitionBytes != len(normalized) {
		t.Fatalf("keyless metadata index = %+v more=%v err=%v", index, more, err)
	}
	if _, err := j.CreateCommandAutomationSchedule(ctx, "acme", commandScheduleInput(t, "acme", plan, definition, "alice")); err != nil {
		t.Fatalf("encrypted schedule binding: %v", err)
	}
	if _, err := j.CreateCommandAutomationWebhookTrigger(ctx, "acme", commandWebhookInput(t, "acme", plan, definition, "cred_cmd_def_crypto", "cmdwhk_def_crypto")); err != nil {
		t.Fatalf("encrypted webhook binding: %v", err)
	}
	if _, err := j.CreateCommandAutomationChainTrigger(ctx, "acme", commandChainInput(t, "acme", plan, definition, "wf_def_crypto_source")); err != nil {
		t.Fatalf("encrypted chain binding: %v", err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 2, definition, strings.Repeat("c", 64), "alice")
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_def_crypto", plan.ID, 2, admission); err != nil {
		t.Fatalf("encrypted run admission: %v", err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO command_automation_versions (automation_id, version, definition_json)
		VALUES (?, 2, ?)`, legacy.ID, string(normalized)); err == nil {
		t.Fatal("old SQL writer inserted a plaintext definition after key initialization")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_automation_versions SET definition_json = ? WHERE automation_id = ? AND version = 1`,
		strings.Replace(string(normalized), "synthetic-private-command", "changed-command", 1), legacy.ID); err == nil {
		t.Fatal("old SQL writer changed a historical plaintext definition after key initialization")
	}
	if _, err := j.db.ExecContext(ctx, `UPDATE command_automation_versions
		SET definition_json = ?, definition_crypto_version = 0, definition_plaintext_bytes = NULL, definition_sha256 = NULL
		WHERE automation_id = ? AND version = 1`, string(normalized), plan.ID); err == nil {
		t.Fatal("encrypted definition downgraded to plaintext")
	}
	// Both versions have identical plaintext receipts, so this tests the AAD
	// version binding rather than merely failing a size or hash comparison.
	if _, err := j.db.ExecContext(ctx, `UPDATE command_automation_versions SET definition_json = ? WHERE automation_id = ? AND version = 2`,
		string(storedV1), plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetCommandAutomationVersion(ctx, "acme", plan.ID, 2); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("ciphertext crossed version identity: %v", err)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := verifyCommandAutomationScheduleBindingTx(ctx, tx, j, "acme", commandScheduleInput(t, "acme", plan, definition, "alice")); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered definition accepted for schedule: %v", err)
	}
	if err := verifyCommandAutomationWebhookBindingTx(ctx, tx, j, "acme", commandWebhookInput(t, "acme", plan, definition, "cred_cmd_def_crypto", "cmdwhk_def_tampered")); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered definition accepted for webhook: %v", err)
	}
	if err := verifyCommandAutomationChainBindingTx(ctx, tx, j, "acme", commandChainInput(t, "acme", plan, definition, "wf_def_crypto_source")); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered definition accepted for chain: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_def_tampered", plan.ID, 2, admission); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("tampered definition admitted as run: %v", err)
	}
}

func TestLegacyMalformedCommandDefinitionRemainsInertAfterKeyInitialization(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_def_malformed", "def-malformed", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	const malformedDefinition = `{"steps":[{"name":"missing-command"}]}`
	if _, err := j.db.ExecContext(ctx, `INSERT INTO command_automation_versions (automation_id, version, definition_json) VALUES (?, 2, ?)`, plan.ID, malformedDefinition); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x72}, 32), nil); err != nil {
		t.Fatal(err)
	}
	got, err := j.GetCommandAutomationVersion(ctx, "acme", plan.ID, 2)
	if err != nil || string(got.DefinitionJSON) != malformedDefinition {
		t.Fatalf("malformed historical definition = %+v, %v", got, err)
	}
	index, _, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", plan.ID, 2, 0)
	if err != nil || len(index) != 2 || index[0].DefinitionBytes != len(malformedDefinition) {
		t.Fatalf("malformed historical summary = %+v, %v", index, err)
	}
	if _, _, err := commandautomations.Normalize(got.DefinitionJSON); err == nil {
		t.Fatal("malformed historical definition became executable")
	}
}

func TestInvalidLegacyCommandDefinitionFailsClosedAfterKeyInitialization(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_def_invalid_json", "def-invalid-json", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO command_automation_versions (automation_id, version, definition_json) VALUES (?, 2, ?)`, plan.ID, `{broken`); err != nil {
		t.Fatal(err)
	}
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x73}, 32), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetCommandAutomationVersion(ctx, "acme", plan.ID, 2); !errors.Is(err, payloadcrypto.ErrInvalidEnvelope) {
		t.Fatalf("invalid JSON version read = %v", err)
	}
	if _, _, err := j.ListCommandAutomationVersionSummariesPage(ctx, "acme", plan.ID, 2, 0); err == nil {
		t.Fatal("invalid JSON version was listed as usable metadata")
	}
}
