package server

import (
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMemberWorkflowViewHidesAdminMutations(t *testing.T) {
	html := workflowDetailBody(workflowDetailData{
		Slug:        "member-workflow",
		ID:          "wf_member",
		ReadOnly:    true,
		EditEnabled: false,
		DAG:         `{"steps":[{"name":"send","kind":"http"}]}`,
		Triggers:    nil,
	})
	for _, forbidden := range []string{
		`/workflows/member-workflow/enable`,
		`/workflows/member-workflow/disable`,
		`/workflows/member-workflow/delete`,
		`/workflows/member-workflow/minutes-saved`,
		`/workflows/member-workflow/rate-limit`,
		`/workflows/member-workflow/triggers`,
		`/workflows/member-workflow/notifications`,
		`/workflows/member-workflow/code`,
		`data-editable="true"`,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("member workflow view contains admin mutation %q", forbidden)
		}
	}
	if !strings.Contains(html, `/workflows/member-workflow/run`) {
		t.Fatal("member workflow view should retain tenant-scoped manual dispatch")
	}
	if !strings.Contains(html, "Workflow configuration is read-only for members") {
		t.Fatal("member workflow view should explain the admin boundary")
	}
}

func TestAdminWorkflowFormsPreserveTenantQuery(t *testing.T) {
	html := workflowDetailBody(workflowDetailData{
		Slug:                "shared",
		ID:                  "wf_acme",
		CurrentVersion:      7,
		WorkflowActionQuery: "?tenant=acme",
		EditEnabled:         true,
		DAG:                 `{"steps":[{"name":"send","kind":"http"}]}`,
		Code:                "package main\n",
	})
	for _, want := range []string{
		`action="/workflows/shared/run?tenant=acme"`,
		`action="/workflows/shared/disable?tenant=acme"`,
		`action="/workflows/shared/enable?tenant=acme"`,
		`action="/workflows/shared/delete?tenant=acme"`,
		`action="/workflows/shared/minutes-saved?tenant=acme"`,
		`action="/workflows/shared/rate-limit?tenant=acme"`,
		`action="/workflows/shared/code?tenant=acme"`,
		`action="/workflows/shared/dag?tenant=acme"`,
		`data-action-query="?tenant=acme"`,
		`data-expected-version="7"`,
		`name="expected_version" value="7"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("admin workflow HTML missing %s", want)
		}
	}
}

func TestWorkflowDetailShowsImmutableProofAndKeepsWarningsDataOnly(t *testing.T) {
	verified := workflowDetailBody(workflowDetailData{
		Slug:            "verified-workflow",
		ID:              "wf_verified",
		CurrentVersion:  4,
		ArtifactSHA256:  strings.Repeat("a", 64),
		FlowProofStatus: "verified",
		DAG:             `{"steps":[{"name":"send","kind":"http"}]}`,
	})
	for _, want := range []string{
		"Immutable version",
		"<code>v4</code>",
		"Artifact SHA-256",
		strings.Repeat("a", 64),
		`<span class="tag tag-on">verified</span>`,
		"Durable flow proof verified against the immutable artifact and retained source",
		"author-declared dependency graph",
		"runtime step receipts show the actual path",
	} {
		if !strings.Contains(verified, want) {
			t.Fatalf("verified workflow view missing %q", want)
		}
	}
	if strings.Contains(verified, "inspection data only") {
		t.Fatal("verified workflow view should not warn that the flow is unverified")
	}

	unverified := workflowDetailBody(workflowDetailData{
		Slug:            "tampered-workflow",
		ID:              "wf_tampered",
		CurrentVersion:  5,
		ArtifactSHA256:  strings.Repeat("b", 64),
		FlowProofStatus: "mismatch",
		FlowProofReason: `retained source <script>alert("x")</script> mismatched`,
		DAG:             `{"steps":[{"name":"send","kind":"http"}]}`,
	})
	for _, want := range []string{
		`<span class="tag tag-warn">mismatch</span>`,
		"inspection data only",
		`retained source &lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; mismatched`,
	} {
		if !strings.Contains(unverified, want) {
			t.Fatalf("unverified workflow view missing %q", want)
		}
	}
	if strings.Contains(unverified, `<script>alert("x")</script>`) {
		t.Fatal("proof reason must remain escaped display data")
	}
}

func TestMemberHomeHidesAuthoringControls(t *testing.T) {
	html := homeBody(homeData{GeneratorEnabled: false, AdminActions: false})
	for _, forbidden := range []string{`/workflows/new`, `action="/generate"`, `--mcp-allow-authoring`} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("member home contains authoring control %q", forbidden)
		}
	}
	if !strings.Contains(html, "Workflow authoring and configuration are administrator-only") {
		t.Fatal("member home should explain the admin boundary")
	}
}

func TestAdminHomeCodegenSelectsTenantAndExplainsReviewGate(t *testing.T) {
	html := homeBody(homeData{
		AdminActions:     true,
		GeneratorEnabled: true,
		GeneratorTenants: []journal.Tenant{{TenantID: "default"}, {TenantID: "acme"}},
		GeneratorTenant:  "acme",
	})
	for _, want := range []string{
		`action="/generate"`,
		`name="tenant_id"`,
		`value="acme" selected`,
		"stages the immutable artifact disabled for review",
		"Enable it from the workflow page only after checking the source and flow",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("admin codegen form missing %q", want)
		}
	}
}
