package server

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func journalForServerTest(t *testing.T) *journal.Journal {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "t.db")
	if err := writePristineTestSQLite(dbPath); err != nil {
		t.Fatalf("pristine SQLite fixture: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return journal.New(db, journal.EngineSQLite)
}

func withChiParam(r *http.Request, key, val string) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

func TestTenantsAdminPage(t *testing.T) {
	t.Parallel()
	j := journalForServerTest(t)
	s := &Server{Journal: j, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	admin := auth.User{ID: "a1", Role: auth.RoleAdmin}

	// Create a tenant via the form.
	form := url.Values{
		"tenant_id":           {"acme"},
		"name":                {"Acme"},
		"plan":                {"pro"},
		"max_concurrent_runs": {"5"},
		"max_queued_runs":     {"100"},
		"monthly_run_quota":   {"1000"},
	}
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(withUser(req.Context(), admin))
	rec := httptest.NewRecorder()
	s.tenantsUpsert(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("upsert code = %d, want 303", rec.Code)
	}
	got, err := j.GetTenant(context.Background(), "acme")
	if err != nil || got.MaxConcurrentRuns != 5 || got.MaxQueuedRuns != 100 || got.MonthlyRunQuota != 1000 {
		t.Fatalf("tenant not persisted: %+v err=%v", got, err)
	}

	// GET renders the page with the tenant.
	greq := httptest.NewRequest(http.MethodGet, "/tenants", nil).WithContext(withUser(context.Background(), admin))
	grec := httptest.NewRecorder()
	s.tenants(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("get code = %d, want 200", grec.Code)
	}
	if !strings.Contains(grec.Body.String(), "acme") {
		t.Fatal("rendered page missing the acme tenant")
	}

	// A member is forbidden.
	mreq := httptest.NewRequest(http.MethodGet, "/tenants", nil).
		WithContext(withUser(context.Background(), auth.User{ID: "m1", Role: auth.RoleMember}))
	mrec := httptest.NewRecorder()
	s.tenants(mrec, mreq)
	if mrec.Code != http.StatusForbidden {
		t.Fatalf("member code = %d, want 403", mrec.Code)
	}

	// Deleting the default tenant is refused (409 from the journal guard).
	dreq := httptest.NewRequest(http.MethodPost, "/tenants/default/delete", nil)
	dreq = dreq.WithContext(withUser(dreq.Context(), admin))
	dreq = withChiParam(dreq, "id", "default")
	drec := httptest.NewRecorder()
	s.tenantsDelete(drec, dreq)
	if drec.Code != http.StatusConflict {
		t.Fatalf("delete default code = %d, want 409", drec.Code)
	}

	// Deleting a real tenant succeeds.
	d2 := httptest.NewRequest(http.MethodPost, "/tenants/acme/delete", nil)
	d2 = d2.WithContext(withUser(d2.Context(), admin))
	d2 = withChiParam(d2, "id", "acme")
	d2rec := httptest.NewRecorder()
	s.tenantsDelete(d2rec, d2)
	if d2rec.Code != http.StatusSeeOther {
		t.Fatalf("delete acme code = %d, want 303", d2rec.Code)
	}
	if _, err := j.GetTenant(context.Background(), "acme"); err == nil {
		t.Fatal("acme should be deleted")
	}
}
