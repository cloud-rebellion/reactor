package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMCPExactInputAndBulkExportRequireExplicitDataExportScope(t *testing.T) {
	t.Parallel()
	for _, scopes := range []*WriteScopes{nil, {}} {
		s, _, _ := newTestServer(t, false)
		s.Scopes = scopes
		s.registerTools()
		for _, name := range []string{"reactor_get_run_input", "reactor_get_run_step_output", "reactor_get_run_logs", "reactor_export_tenant_data"} {
			if _, advertised := s.tools[name]; advertised {
				t.Fatalf("%s advertised without data-export scope: %+v", name, scopes)
			}
			params, err := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.handle(context.Background(), "tools/call", params); !errors.Is(err, errMethodNotFoundErr) {
				t.Fatalf("%s call without scope = %v, want method not found", name, err)
			}
		}
		if _, ok := s.tools["reactor_get_run"]; !ok {
			t.Fatal("ordinary tenant run inspection disappeared with data export disabled")
		}
	}
}

func TestMCPDataExportReadsAreAuditedAndFailClosedWhenAuditUnavailable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "m.db")
	if err := migrate.Up(context.Background(), slog.Default(), "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	if err := j.EnablePayloadEncryption(context.Background(), bytes.Repeat([]byte{0x31}, 32), nil); err != nil {
		t.Fatal(err)
	}
	s := &Server{Journal: j, Scopes: &WriteScopes{DataExport: true}}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_export_audit", "export-audit", "h", "0.1.0", json.RawMessage(`{}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	secret := "customer-supplied-opaque-value"
	if err := j.CreateRun(ctx, "run_export_audit", "wf_export_audit", "manual", json.RawMessage(`{"value":"`+secret+`"}`)); err != nil {
		t.Fatal(err)
	}
	var storedMeta, storedInput []byte
	if err := db.QueryRowContext(ctx, `SELECT trigger_meta, trigger_input FROM runs WHERE id = ?`, "run_export_audit").Scan(&storedMeta, &storedInput); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedMeta, []byte(secret)) || bytes.Contains(storedInput, []byte(secret)) {
		t.Fatal("trigger input persisted in plaintext")
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_export_audit", "external", 1, 1, "private-caller-key", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_export_audit", "external", 1, 1, json.RawMessage(`{"value":"`+secret+`"}`), "provider failed: "+secret); err != nil {
		t.Fatal(err)
	}
	var storedStepOutput []byte
	var storedStepError string
	var stepVersion int
	if err := db.QueryRowContext(ctx, `SELECT output_jsonb, error_text, payload_crypto_version
		FROM steps WHERE run_id = ? AND step_name = ? AND seq = ? AND attempt = ?`,
		"run_export_audit", "external", 1, 1).Scan(&storedStepOutput, &storedStepError, &stepVersion); err != nil {
		t.Fatal(err)
	}
	if stepVersion != 1 || bytes.Contains(storedStepOutput, []byte(secret)) || strings.Contains(storedStepError, secret) {
		t.Fatalf("step result persisted plaintext: version=%d output=%q error=%q", stepVersion, storedStepOutput, storedStepError)
	}
	if err := j.SaveRunLogs(ctx, "run_export_audit", []string{"provider log: " + secret}); err != nil {
		t.Fatal(err)
	}
	defaultRead := callOperationalTool(t, &Server{Journal: j}, "reactor_get_run", map[string]any{"run_id": "run_export_audit"}, false)
	if strings.Contains(string(defaultRead), secret) || strings.Contains(string(defaultRead), "private-caller-key") ||
		!strings.Contains(string(defaultRead), `"output_redacted":true`) ||
		!strings.Contains(string(defaultRead), `"error_redacted":true`) ||
		!strings.Contains(string(defaultRead), `"trigger_meta_redacted":true`) ||
		!strings.Contains(string(defaultRead), `"idempotency_key_redacted":true`) {
		t.Fatalf("default run view exposed execution data or missed receipts: %s", defaultRead)
	}
	inputRead := callOperationalTool(t, s, "reactor_get_run_input", map[string]any{"run_id": "run_export_audit"}, false)
	var inputView struct {
		InputBase64 string `json:"input_base64"`
	}
	if err := json.Unmarshal(inputRead, &inputView); err != nil {
		t.Fatal(err)
	}
	exactInput, err := base64.StdEncoding.DecodeString(inputView.InputBase64)
	if err != nil || string(exactInput) != `{"value":"`+secret+`"}` {
		t.Fatalf("scoped MCP input did not return decrypted exact bytes: %q, %v", exactInput, err)
	}
	step := callOperationalTool(t, s, "reactor_get_run_step_output", map[string]any{"run_id": "run_export_audit", "step_name": "external", "seq": 1, "attempt": 1}, false)
	if !strings.Contains(string(step), secret) {
		t.Fatalf("scoped step read omitted persisted output: %s", step)
	}
	logs := callOperationalTool(t, s, "reactor_get_run_logs", map[string]any{"run_id": "run_export_audit"}, false)
	if !strings.Contains(string(logs), secret) {
		t.Fatalf("scoped log read omitted persisted line: %s", logs)
	}
	callOperationalTool(t, s, "reactor_export_tenant_data", map[string]any{"max_runs": 1}, false)
	entries, err := j.ListMCPAuditForTenant(ctx, journal.DefaultTenant, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("data export audit rows = %d, want 4", len(entries))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.ToolName] = true
		if entry.Outcome != "succeeded" || strings.Contains(entry.Target, secret) || strings.Contains(string(entry.Detail), secret) {
			t.Fatalf("unsafe data export audit receipt: %+v", entry)
		}
	}
	if !seen["reactor_get_run_input"] || !seen["reactor_get_run_step_output"] || !seen["reactor_get_run_logs"] || !seen["reactor_export_tenant_data"] {
		t.Fatalf("missing scoped read audit receipts: %+v", entries)
	}

	// A broken audit store must not turn the successful data query into an
	// unlogged export. The handler has read the data, but the MCP response is
	// replaced before it reaches the caller.
	if _, err := db.ExecContext(ctx, "DROP TABLE mcp_audit"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"reactor_get_run_input", map[string]any{"run_id": "run_export_audit"}},
		{"reactor_get_run_step_output", map[string]any{"run_id": "run_export_audit", "step_name": "external", "seq": 1, "attempt": 1}},
		{"reactor_get_run_logs", map[string]any{"run_id": "run_export_audit"}},
		{"reactor_export_tenant_data", map[string]any{"max_runs": 1}},
	} {
		response := callOperationalTool(t, s, tc.name, tc.args, true)
		if !strings.Contains(string(response), "data-export audit unavailable") || strings.Contains(string(response), secret) || strings.Contains(string(response), "input_base64") {
			t.Fatalf("%s returned data without a durable access audit: %s", tc.name, response)
		}
	}
}

func TestHTTPMCPRunInputPagesPreserveExactBytesAndDigest(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.Scopes = &WriteScopes{DataExport: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_input_pages", "input-pages", "h", "0.1.0", json.RawMessage(`{}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	// Keep the payload valid JSON while making it cross the MCP page boundary.
	payload := []byte(`"` + strings.Repeat("x", maxMCPRunInputPageBytes+123) + `"`)
	if err := j.CreateRun(ctx, "run_input_pages", "wf_input_pages", "manual", payload); err != nil {
		t.Fatal(err)
	}

	firstRaw := callOperationalTool(t, s, "reactor_get_run_input", map[string]any{
		"run_id": "run_input_pages", "limit_bytes": maxMCPRunInputPageBytes,
	}, false)
	var first struct {
		InputSHA256    string `json:"input_sha256"`
		ComputedSHA256 string `json:"computed_sha256"`
		DigestStatus   string `json:"digest_status"`
		DigestVerified bool   `json:"digest_verified"`
		InputBase64    string `json:"input_base64"`
		TotalBytes     int    `json:"total_bytes"`
		OffsetBytes    int    `json:"offset_bytes"`
		HasMore        bool   `json:"has_more"`
		NextOffset     int    `json:"next_offset_bytes"`
	}
	if err := json.Unmarshal(firstRaw, &first); err != nil {
		t.Fatal(err)
	}
	if !first.HasMore || first.NextOffset != maxMCPRunInputPageBytes || first.OffsetBytes != 0 || first.TotalBytes != len(payload) {
		t.Fatalf("first page metadata = %+v", first)
	}
	firstBytes, err := base64.StdEncoding.DecodeString(first.InputBase64)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstBytes) != maxMCPRunInputPageBytes {
		t.Fatalf("first page bytes = %d, want %d", len(firstBytes), maxMCPRunInputPageBytes)
	}
	if first.DigestStatus != "verified" || !first.DigestVerified || first.InputSHA256 == "" || first.InputSHA256 != first.ComputedSHA256 {
		t.Fatalf("digest receipt = %+v", first)
	}

	secondRaw := callOperationalTool(t, s, "reactor_get_run_input", map[string]any{
		"run_id": "run_input_pages", "offset_bytes": first.NextOffset, "limit_bytes": maxMCPRunInputPageBytes,
	}, false)
	var second struct {
		InputBase64 string `json:"input_base64"`
		HasMore     bool   `json:"has_more"`
	}
	if err := json.Unmarshal(secondRaw, &second); err != nil {
		t.Fatal(err)
	}
	if second.HasMore {
		t.Fatal("second page unexpectedly has more data")
	}
	secondBytes, err := base64.StdEncoding.DecodeString(second.InputBase64)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(firstBytes, secondBytes...)
	if string(combined) != string(payload) {
		t.Fatalf("paged input changed bytes: got %d bytes, want %d", len(combined), len(payload))
	}
	wantHash := sha256.Sum256(payload)
	if first.InputSHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("input hash = %q, want %x", first.InputSHA256, wantHash)
	}
}

func TestHTTPMCPRunInputRefusesForeignRunsAndBoundsPages(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.Scopes = &WriteScopes{DataExport: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_input_acme", "input-acme", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_input_globex", "input-globex", "h", "0.1.0", json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_input_acme", "wf_input_acme", "manual", json.RawMessage(`{"tenant":"acme"}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_input_globex", "wf_input_globex", "manual", json.RawMessage(`{"tenant":"globex"}`)); err != nil {
		t.Fatal(err)
	}
	s.TenantID = "acme"
	callOperationalTool(t, s, "reactor_get_run_input", map[string]any{"run_id": "run_input_globex"}, true)
	callOperationalTool(t, s, "reactor_get_run_input", map[string]any{"run_id": "run_input_acme", "limit_bytes": maxMCPRunInputPageBytes + 1}, true)
	callOperationalTool(t, s, "reactor_get_run_input", map[string]any{"run_id": "run_input_acme", "offset_bytes": maxMCPRunInputOffsetBytes + 1}, true)
	callOperationalTool(t, s, "reactor_get_run_input", map[string]any{"run_id": "run_input_acme", "unexpected": true}, true)
}

func TestHTTPMCPRunInputRejectsStoredInputAboveRetrievalBound(t *testing.T) {
	t.Parallel()
	s, j, _ := newTestServer(t, false)
	s.Scopes = &WriteScopes{DataExport: true}
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_input_large", "input-large", "h", "0.1.0", json.RawMessage(`{}`), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`"` + strings.Repeat("x", maxMCPRunInputTotalBytes) + `"`)
	if err := j.CreateRun(ctx, "run_input_large", "wf_input_large", "manual", payload); err != nil {
		t.Fatal(err)
	}
	callOperationalTool(t, s, "reactor_get_run_input", map[string]any{"run_id": "run_input_large"}, true)
}

func TestRunInputDigestReceiptSurfacesMismatchAndLegacyFallback(t *testing.T) {
	t.Parallel()
	legacyInput := []byte(`{"legacy":true}`)
	want := sha256.Sum256(legacyInput)
	recorded, computed, status, source, verified := runInputDigestReceipt(journal.RunInfo{
		InputSHA256: hex.EncodeToString(want[:]),
		// A nil TriggerInput identifies a row predating raw-input retention.
		TriggerInput: nil,
	}, legacyInput)
	if recorded != hex.EncodeToString(want[:]) || computed != recorded || status != "legacy_fallback" || source != "legacy_trigger_meta" || !verified {
		t.Fatalf("legacy digest receipt = recorded %q computed %q status %q source %q verified %v", recorded, computed, status, source, verified)
	}
	_, _, status, source, verified = runInputDigestReceipt(journal.RunInfo{
		InputSHA256:  "bad-digest",
		TriggerInput: []byte("persisted"),
	}, []byte("persisted"))
	if status != "mismatch" || source != "trigger_input" || verified {
		t.Fatalf("mismatch digest receipt = status %q source %q verified %v", status, source, verified)
	}
}
