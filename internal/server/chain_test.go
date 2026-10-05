package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestChainTriggerCreationFromDashboard(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()

	if err := j.CreateWorkflow(ctx, "wf_src", "src", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflow(ctx, "wf_down", "downstream", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	// dashboard form: POST to the downstream workflow's triggers
	// endpoint with kind=chain + source_slug.
	form := url.Values{
		"kind":        {"chain"},
		"source_slug": {"src"},
		"on_statuses": {"succeeded,failed_dlq"},
	}
	resp := postSameOrigin(t, srv.URL+"/workflows/downstream/triggers", form)
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 303\n%s", resp.StatusCode, body)
	}

	// Both views populate.
	down, _ := j.ChainTriggersDownstreamOf(ctx, "wf_src")
	if len(down) != 1 || down[0].DownstreamSlug != "downstream" {
		t.Fatalf("downstream = %+v", down)
	}
	up, _ := j.ChainTriggersUpstreamOf(ctx, "wf_down")
	if len(up) != 1 || up[0].SourceSlug != "src" {
		t.Fatalf("upstream = %+v", up)
	}

	// Downstream workflow's detail page shows the upstream chain
	// trigger in the standard Triggers table (as kind=workflow_complete).
	body := getBody(t, srv.URL+"/workflows/downstream")
	if !strings.Contains(string(body), "after") || !strings.Contains(string(body), "wf_src") {
		t.Fatalf("downstream detail page should show 'after wf_src' chain row\n%s", string(body)[:min(len(body), 3000)])
	}

	// Source workflow's detail page shows the downstream chain in
	// the "Downstream workflows" section.
	body = getBody(t, srv.URL+"/workflows/src")
	if !strings.Contains(string(body), "Downstream workflows") || !strings.Contains(string(body), "downstream") {
		t.Fatalf("source detail page should show downstream chain\n%s", string(body)[:min(len(body), 3000)])
	}
}

func TestChainTriggerRejectsUnknownSource(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_down", "downstream", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"kind":        {"chain"},
		"source_slug": {"nonexistent-workflow"},
	}
	resp := postSameOrigin(t, srv.URL+"/workflows/downstream/triggers", form)
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 404\n%s", resp.StatusCode, body)
	}
}

func TestDownstreamChainLinkCarriesOwnerTenant(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_link_source", "chain-link-source", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_link_downstream", "shared-downstream", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	// A global admin can have two tenants with the same slug. The rendered
	// chain link must retain the owning tenant or it can open the wrong
	// workflow when the bare-slug lookup chooses another tenant's row.
	if err := j.CreateWorkflowInTenant(ctx, "wf_chain_link_foreign", "shared-downstream", "h", "0.1.0", json.RawMessage(`{}`), "globex"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateChainTrigger(ctx, "wf_chain_link_downstream", "wf_chain_link_source", "succeeded"); err != nil {
		t.Fatal(err)
	}

	rows, err := j.ChainTriggersDownstreamOf(ctx, "wf_chain_link_source")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DownstreamTenantID != "acme" {
		t.Fatalf("downstream rows = %+v, want one acme-owned row", rows)
	}
	html := renderDownstreamChainSection(rows)
	if !strings.Contains(html, `href="/workflows/shared-downstream?tenant=acme"`) {
		t.Fatalf("downstream link lost owner tenant: %s", html)
	}
}
