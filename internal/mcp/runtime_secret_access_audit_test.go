package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMCPRuntimeSecretAccessAuditIsTenantScopedAndPaged(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.TenantID = "tenant-a"
	ctx := context.Background()
	for _, row := range []struct{ workflowID, slug, tenant, runID string }{
		{"wf_secret_audit_a", "secret-audit-a", "tenant-a", "run_secret_audit_a"},
		{"wf_secret_audit_b", "secret-audit-b", "tenant-b", "run_secret_audit_b"},
	} {
		if err := j.CreateWorkflowInTenant(ctx, row.workflowID, row.slug, "h", "0.1.0", json.RawMessage(`{}`), row.tenant); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateRun(ctx, row.runID, row.workflowID, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ tenant, workflowID, runID, ref, kind string }{
		{"tenant-a", "wf_secret_audit_a", "run_secret_audit_a", "cred_safe", "vault"},
		{"tenant-a", "wf_secret_audit_a", "run_secret_audit_a", "oauth:conn_safe", "oauth"},
		{"tenant-b", "wf_secret_audit_b", "run_secret_audit_b", "cred_foreign", "vault"},
	} {
		if err := j.AppendRuntimeSecretAccess(ctx, "", journal.RuntimeSecretAccess{
			TenantID: row.tenant, WorkflowID: row.workflowID, RunID: row.runID,
			SecretRef: row.ref, SecretKind: row.kind,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for offset := 0; offset < 2; offset++ {
		raw := callOperationalTool(t, s, "reactor_list_runtime_secret_access_audit", map[string]any{
			"limit": 1, "offset": offset,
		}, false)
		if strings.Contains(string(raw), "cred_foreign") || strings.Contains(string(raw), "run_secret_audit_b") {
			t.Fatalf("foreign tenant runtime audit leaked: %s", raw)
		}
		var page struct {
			Entries    []journal.RuntimeSecretAccess `json:"entries"`
			HasMore    bool                          `json:"has_more"`
			NextOffset int                           `json:"next_offset"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Entries) != 1 || page.Entries[0].TenantID != "tenant-a" || page.Entries[0].At.IsZero() {
			t.Fatalf("scoped runtime audit page = %+v", page)
		}
		if offset == 0 && (!page.HasMore || page.NextOffset != 1) || offset == 1 && page.HasMore {
			t.Fatalf("runtime audit continuation = %+v", page)
		}
		seen[page.Entries[0].SecretRef] = true
	}
	if !seen["cred_safe"] || !seen["oauth:conn_safe"] || len(seen) != 2 {
		t.Fatalf("runtime audit pages omitted or duplicated receipts: %+v", seen)
	}
	callOperationalTool(t, s, "reactor_list_runtime_secret_access_audit", map[string]any{"limit": 101}, true)
	callOperationalTool(t, s, "reactor_list_runtime_secret_access_audit", map[string]any{"offset": -1}, true)
	callOperationalTool(t, s, "reactor_list_runtime_secret_access_audit", map[string]any{"unexpected": true}, true)
}
