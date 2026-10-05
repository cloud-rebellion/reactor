package journal

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMCPAuditIsTenantScopedAndRedacted(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.AppendMCPAudit(ctx, MCPAuditEntry{
		TenantID: "acme", ActorID: "usr_1", ToolName: "reactor_dispatch_workflow",
		Outcome: "succeeded", Target: "slug=orders", Detail: json.RawMessage(`{"state":"enabled"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendMCPAudit(ctx, MCPAuditEntry{
		TenantID: "other", ToolName: "reactor_delete_workflow", Outcome: "failed",
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := j.ListMCPAuditForTenant(ctx, "acme", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != "acme" || rows[0].ActorID != "usr_1" || rows[0].ToolName != "reactor_dispatch_workflow" {
		t.Fatalf("scoped audit rows = %+v", rows)
	}
	if string(rows[0].Detail) != `{"state":"enabled"}` {
		t.Fatalf("detail = %s", rows[0].Detail)
	}
	if err := j.AppendMCPAudit(ctx, MCPAuditEntry{TenantID: "acme", ToolName: "x", Outcome: "unknown"}); err == nil {
		t.Fatal("unsupported outcome accepted")
	}
	if err := j.AppendMCPAudit(ctx, MCPAuditEntry{TenantID: "acme", ToolName: "x", Outcome: "succeeded", Detail: json.RawMessage(`not-json`)}); err == nil {
		t.Fatal("invalid detail accepted")
	}
	if _, err := j.ListMCPAuditForTenant(ctx, "acme", 1, -1); err == nil {
		t.Fatal("negative offset accepted")
	}
}
