package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/go-chi/chi/v5"
)

type validationFailureGenerator struct {
	err error
}

func (g validationFailureGenerator) GenerateFromBrief(context.Context, string) (string, string, string, error) {
	return "", "", "", g.err
}

func TestGenerateValidationFailureReturnsActionable422(t *testing.T) {
	t.Parallel()
	srv := &Server{Generator: validationFailureGenerator{
		err: &codegen.ValidationError{Attempts: 3, Err: errors.New("go vet: undefined: sendEmail")},
	}}
	r := chi.NewRouter()
	r.Post("/generate", srv.generateWorkflow)
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/generate", "application/x-www-form-urlencoded", strings.NewReader("brief=send+an+email"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", resp.StatusCode, body)
	}
	for _, want := range []string{"validation failed after 3 attempts", "undefined: sendEmail"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestDashboardGeneratedWorkflowsStageDisabledAndKeepTenant(t *testing.T) {
	t.Parallel()
	req := dashboardBuildRequest("/state", "welcome", "/tmp/generated", "0.1.0", "acme")
	if !req.StartDisabled {
		t.Fatal("dashboard codegen must stage generated workflows disabled until review")
	}
	if req.TenantID != "acme" {
		t.Fatalf("dashboard codegen tenant = %q, want acme", req.TenantID)
	}
	if !req.RetainSource {
		t.Fatal("dashboard codegen must retain the immutable source for review")
	}
}

func TestGenerateTenantPinsMembersAndRejectsUnknownAdminTenant(t *testing.T) {
	t.Parallel()
	srv, j, _ := newTestServer(t)
	_ = srv
	ctx := context.Background()
	if err := j.UpsertTenant(ctx, journal.Tenant{TenantID: "acme", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}

	memberReq := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader("tenant_id=globex"))
	memberReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := memberReq.ParseForm(); err != nil {
		t.Fatal(err)
	}
	memberReq = memberReq.WithContext(withUser(memberReq.Context(), auth.User{ID: "m", Role: auth.RoleMember, TenantID: "acme"}))
	got, err := (&Server{Journal: j}).generateTenant(memberReq)
	if err != nil || got != "acme" {
		t.Fatalf("member tenant = %q, err=%v; want pinned acme", got, err)
	}

	adminReq := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader("tenant_id=globex"))
	adminReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := adminReq.ParseForm(); err != nil {
		t.Fatal(err)
	}
	adminReq = adminReq.WithContext(withUser(adminReq.Context(), auth.User{ID: "a", Role: auth.RoleAdmin}))
	if got, err := (&Server{Journal: j}).generateTenant(adminReq); err == nil || got != "" {
		t.Fatalf("unknown admin tenant = %q, err=%v; want fail closed", got, err)
	}
}
