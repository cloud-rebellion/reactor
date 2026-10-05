package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestHomeAvailabilityAndRunNowStayWithWorkflowTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j := journalForServerTest(t)
	for _, wf := range []struct{ id, tenant string }{{"wf_acme", "acme"}, {"wf_globex", "globex"}} {
		if err := j.CreateWorkflowInTenant(ctx, wf.id, "shared", "h", "0.1.0", json.RawMessage(`{}`), wf.tenant); err != nil {
			t.Fatal(err)
		}
	}
	wfs, err := j.ListWorkflows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New(t.TempDir())
	if err := reg.ClaimTenant("shared", "acme"); err != nil {
		t.Fatal(err)
	}
	acmeBinary := filepath.Join(reg.Root, "shared", "workflow")
	if err := os.WriteFile(acmeBinary, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Server{Journal: j, Registry: reg}

	available := s.availableHomeWorkflows(wfs)
	if !available[workflowHomeKey{TenantID: "acme", Slug: "shared"}] || available[workflowHomeKey{TenantID: "globex", Slug: "shared"}] {
		t.Fatalf("tenant deployment projection = %#v; want only acme", available)
	}
	adminHTML := homeBody(homeData{ShowTenant: true, Workflows: wfs, Available: available})
	acmeRow := homeWorkflowRow(t, adminHTML, "wf_acme")
	globexRow := homeWorkflowRow(t, adminHTML, "wf_globex")
	if !strings.Contains(acmeRow, `tag-on">deployed`) || !strings.Contains(acmeRow, `action="/workflows/shared/run?tenant=acme"`) {
		t.Fatalf("acme row omitted its own deployed state/action: %s", acmeRow)
	}
	if !strings.Contains(globexRow, `class="warn">missing`) || strings.Contains(globexRow, `run now`) {
		t.Fatalf("globex row borrowed acme's binary/action: %s", globexRow)
	}

	admin := auth.User{ID: "admin", Role: auth.RoleAdmin}
	request := httptest.NewRequest(http.MethodPost, "/workflows/shared/run?tenant=acme", nil)
	request = request.WithContext(withUser(request.Context(), admin))
	if got, err := s.workflowIDForViewer(request, "shared"); err != nil || got != "wf_acme" {
		t.Fatalf("admin Run now target = %q, %v; want wf_acme", got, err)
	}

	// The same row remains a plain slug action for a tenant-scoped member;
	// their authenticated tenant, not a query parameter, supplies the scope.
	memberHTML := homeBody(homeData{ShowTenant: false, Workflows: []journal.Workflow{{ID: "wf_acme", TenantID: "acme", Slug: "shared"}}, Available: available})
	memberRow := homeWorkflowRow(t, memberHTML, "wf_acme")
	if !strings.Contains(memberRow, `action="/workflows/shared/run"`) || strings.Contains(memberRow, `?tenant=`) {
		t.Fatalf("member Run now action changed its tenant-scoped form: %s", memberRow)
	}

	// Move the only executable to the isolated namespace for the other
	// tenant. Neither cached slug availability nor row ordering may keep the
	// old tenant marked deployed.
	if err := os.Remove(acmeBinary); err != nil {
		t.Fatal(err)
	}
	globexDir, err := reg.EnsureScopedTenant("shared", "globex")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(globexDir, "workflow"), []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	available = s.availableHomeWorkflows(wfs)
	adminHTML = homeBody(homeData{ShowTenant: true, Workflows: wfs, Available: available})
	acmeRow = homeWorkflowRow(t, adminHTML, "wf_acme")
	globexRow = homeWorkflowRow(t, adminHTML, "wf_globex")
	if available[workflowHomeKey{TenantID: "acme", Slug: "shared"}] ||
		!available[workflowHomeKey{TenantID: "globex", Slug: "shared"}] ||
		!strings.Contains(acmeRow, `class="warn">missing`) || strings.Contains(acmeRow, `run now`) ||
		!strings.Contains(globexRow, `action="/workflows/shared/run?tenant=globex"`) {
		t.Fatalf("swapped tenant availability/action incorrect: acme=%s globex=%s", acmeRow, globexRow)
	}
	request = httptest.NewRequest(http.MethodPost, "/workflows/shared/run?tenant=globex", nil)
	request = request.WithContext(withUser(request.Context(), admin))
	if got, err := s.workflowIDForViewer(request, "shared"); err != nil || got != "wf_globex" {
		t.Fatalf("swapped admin Run now target = %q, %v; want wf_globex", got, err)
	}
	member := auth.User{ID: "member", Role: auth.RoleMember, TenantID: "acme"}
	request = httptest.NewRequest(http.MethodPost, "/workflows/shared/run?tenant=globex", nil)
	request = request.WithContext(withUser(request.Context(), member))
	if got, err := s.workflowIDForViewer(request, "shared"); err != nil || got != "wf_acme" {
		t.Fatalf("member query overrode authenticated tenant: %q, %v", got, err)
	}
}

func homeWorkflowRow(t *testing.T, html, workflowID string) string {
	t.Helper()
	index := strings.Index(html, `<code>`+workflowID+`</code>`)
	if index < 0 {
		t.Fatalf("workflow %q absent from home", workflowID)
	}
	start := strings.LastIndex(html[:index], "<tr>")
	end := strings.Index(html[index:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("workflow %q has no complete table row", workflowID)
	}
	return html[start : index+end+len("</tr>")]
}
