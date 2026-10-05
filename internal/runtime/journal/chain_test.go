package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCreateChainTriggerRejectsSelfLoop(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	if _, err := j.CreateChainTrigger(context.Background(), "wf_1", "wf_1", "succeeded"); err == nil {
		t.Fatal("self-loop should have been rejected")
	}
}

// TestCreateChainTriggerRejectsCycle is the regression test for the
// ship-blocker where only direct self-loops were rejected: an A->B->C->A
// chain would dispatch forever. The third edge closing the loop must be
// refused at create time.
func TestCreateChainTriggerRejectsCycle(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, slug := range []string{"wf_a", "wf_b", "wf_c"} {
		if err := j.CreateWorkflow(ctx, slug, slug, "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	// a -> b (b fires when a completes), b -> c. Both fine.
	if _, err := j.CreateChainTrigger(ctx, "wf_b", "wf_a", ""); err != nil {
		t.Fatalf("a->b: %v", err)
	}
	if _, err := j.CreateChainTrigger(ctx, "wf_c", "wf_b", ""); err != nil {
		t.Fatalf("b->c: %v", err)
	}
	// c -> a closes the cycle a->b->c->a and must be rejected.
	if _, err := j.CreateChainTrigger(ctx, "wf_a", "wf_c", ""); err == nil {
		t.Fatal("cycle-closing chain trigger should have been rejected")
	}
}

func TestDisabledChainCannotResumeAfterTopologyChanges(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_b", "b", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	id, err := j.CreateChainTrigger(ctx, "wf_b", "wf_1", "succeeded")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetTriggerStateForWorkflow(ctx, id, "wf_b", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateChainTrigger(ctx, "wf_1", "wf_b", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := j.SetTriggerStateForWorkflow(ctx, id, "wf_b", "active"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dashboard-style resume accepted a cycle: %v", err)
	}
	if err := j.SetTriggerState(ctx, id, "active"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CLI-style resume accepted a cycle: %v", err)
	}
	row, err := j.GetTriggerForWorkflow(ctx, id, "wf_b")
	if err != nil || row.State != "disabled" {
		t.Fatalf("rejected resume changed trigger: state=%q err=%v", row.State, err)
	}
}

func TestCreateChainTriggerRoundTrip(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_down", "downstream", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	id, err := j.CreateChainTrigger(ctx, "wf_down", "wf_1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "trg_") {
		t.Fatalf("id = %q", id)
	}

	got, err := j.ChainTriggersForSource(ctx, "wf_1", "succeeded")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].WorkflowID != "wf_down" {
		t.Fatalf("got = %+v", got)
	}
	// Default on_statuses = succeeded only; failed should not fire.
	got, _ = j.ChainTriggersForSource(ctx, "wf_1", "failed")
	if len(got) != 0 {
		t.Fatalf("failed should not fire under default succeeded-only route: %+v", got)
	}
}

func TestChainTriggerOnStatusesCSV(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_down", "downstream", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateChainTrigger(ctx, "wf_down", "wf_1", "succeeded,failed_dlq"); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"succeeded", "failed_dlq"} {
		got, _ := j.ChainTriggersForSource(ctx, "wf_1", status)
		if len(got) != 1 {
			t.Fatalf("%s should fire: %+v", status, got)
		}
	}
	got, _ := j.ChainTriggersForSource(ctx, "wf_1", "failed")
	if len(got) != 0 {
		t.Fatalf("failed should not fire: %+v", got)
	}
}

func TestChainTriggersForSourceFencesLegacyCrossTenantRows(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, row := range []struct {
		id, slug, tenant string
	}{
		{"wf_src_acme", "src-acme", "acme"},
		{"wf_down_acme", "down-acme", "acme"},
		{"wf_down_globex", "down-globex", "globex"},
	} {
		if err := j.CreateWorkflowInTenant(ctx, row.id, row.slug, "h", "1", json.RawMessage(`{}`), row.tenant); err != nil {
			t.Fatal(err)
		}
	}
	// A valid same-tenant row proves the fence does not disable normal chain
	// delivery. The two following rows model imports/restores that left either
	// the trigger marker or the downstream relation crossing tenants.
	const insert = `INSERT INTO triggers
		(id, tenant_id, workflow_id, kind, config_json, state, source_workflow_id)
		VALUES ($1, $2, $3, 'workflow_complete', $4, 'active', $5)`
	rows := []struct {
		id, tenant, downstream string
	}{
		{"trg_chain_valid", "acme", "wf_down_acme"},
		{"trg_chain_foreign_marker", "globex", "wf_down_globex"},
		{"trg_chain_foreign_downstream", "acme", "wf_down_globex"},
	}
	for _, row := range rows {
		if _, err := j.db.ExecContext(ctx, j.bind(insert), row.id, row.tenant, row.downstream,
			`{"source_workflow_id":"wf_src_acme","on_statuses":"succeeded"}`, "wf_src_acme"); err != nil {
			t.Fatalf("insert legacy row %s: %v", row.id, err)
		}
	}

	got, err := j.ChainTriggersForSource(ctx, "wf_src_acme", "succeeded")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "trg_chain_valid" || got[0].TenantID != "acme" {
		t.Fatalf("chain rows = %+v, want only valid same-tenant row", got)
	}
	downstream, err := j.ChainTriggersDownstreamOf(ctx, "wf_src_acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(downstream) != 1 || downstream[0].TriggerID != "trg_chain_valid" || downstream[0].DownstreamTenantID != "acme" {
		t.Fatalf("downstream projection exposed a cross-tenant row: %+v", downstream)
	}
	upstream, err := j.ChainTriggersUpstreamOf(ctx, "wf_down_acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(upstream) != 1 || upstream[0].TriggerID != "trg_chain_valid" || upstream[0].SourceWorkflowID != "wf_src_acme" {
		t.Fatalf("upstream projection exposed a cross-tenant row: %+v", upstream)
	}
}

func TestChainTriggersDownstreamOfAndUpstreamOf(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_down", "downstream", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateChainTrigger(ctx, "wf_down", "wf_1", "succeeded"); err != nil {
		t.Fatal(err)
	}

	down, err := j.ChainTriggersDownstreamOf(ctx, "wf_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(down) != 1 || down[0].DownstreamSlug != "downstream" {
		t.Fatalf("downstream view = %+v", down)
	}

	up, err := j.ChainTriggersUpstreamOf(ctx, "wf_down")
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != 1 || up[0].SourceWorkflowID != "wf_1" || up[0].SourceSlug != "demo" {
		t.Fatalf("upstream view = %+v", up)
	}
}
