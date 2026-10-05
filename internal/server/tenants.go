package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// tenantExport streams a tenant's data as a JSON download (GDPR portability).
func (s *Server) tenantExport(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	exp, err := s.Journal.ExportTenantData(r.Context(), id, 5000)
	if err != nil {
		s.errorPage(w, "export tenant", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="tenant-`+id+`-export.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(exp)
}

// tenantErase deletes a tenant's run history + usage (GDPR right to erasure).
func (s *Server) tenantErase(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := s.Journal.EraseTenantData(r.Context(), id); err != nil {
		s.errorPage(w, "erase tenant data", err)
		return
	}
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}

// tenantView pairs a tenant's config with its live counts, this-month usage,
// and current-period bill estimate for the admin page.
type tenantView struct {
	T       journal.Tenant
	Running int
	Queued  int
	Usage   journal.TenantUsage
	Bill    journal.TenantBill
}

// tenants renders the tenant + quota management page (admin-only). It shows
// each tenant's quotas, current running/queued runs, and metered usage for the
// current calendar month, plus a create/update form.
func (s *Server) tenants(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	ctx := r.Context()
	list, err := s.Journal.ListTenants(ctx)
	if err != nil {
		s.errorPage(w, "list tenants", err)
		return
	}
	since := journal.StartOfMonthUTC()
	views := make([]tenantView, 0, len(list))
	for _, t := range list {
		running, _ := s.Journal.CountRunningForTenant(ctx, t.TenantID)
		queued, _ := s.Journal.CountQueuedForTenant(ctx, t.TenantID)
		usage, _ := s.Journal.TenantUsageSince(ctx, t.TenantID, since)
		bill, _ := s.Journal.TenantBill(ctx, t.TenantID, since)
		views = append(views, tenantView{T: t, Running: running, Queued: queued, Usage: usage, Bill: bill})
	}
	plans, _ := s.Journal.ListPlans(ctx)
	s.renderPage(w, r, page{
		Title:   "Tenants",
		Heading: "Tenants",
		Body:    template.HTML(tenantsBody(views, plans, r.URL.Query().Get("err"))),
	})
}

// tenantsAssignPlan puts a tenant on a plan (admin-only), copying the plan's
// caps onto the tenant.
func (s *Server) tenantsAssignPlan(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	planID := strings.TrimSpace(r.PostFormValue("plan_id"))
	if planID == "" {
		http.Redirect(w, r, "/tenants?err="+urlEsc("pick a plan"), http.StatusSeeOther)
		return
	}
	if err := s.Journal.AssignPlan(r.Context(), id, planID); err != nil {
		s.errorPage(w, "assign plan", err)
		return
	}
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}

// tenantsUpsert creates or updates a tenant from the form (admin-only).
func (s *Server) tenantsUpsert(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("tenant_id"))
	if id == "" {
		http.Redirect(w, r, "/tenants?err="+urlEsc("tenant id is required"), http.StatusSeeOther)
		return
	}
	t := journal.Tenant{
		TenantID:          id,
		Name:              strings.TrimSpace(r.PostFormValue("name")),
		Plan:              strings.TrimSpace(r.PostFormValue("plan")),
		MaxConcurrentRuns: atoiClampZero(r.PostFormValue("max_concurrent_runs")),
		MaxQueuedRuns:     atoiClampZero(r.PostFormValue("max_queued_runs")),
		MonthlyRunQuota:   atoiClampZero(r.PostFormValue("monthly_run_quota")),
		HardCap:           r.PostFormValue("hard_cap") == "on",
		Disabled:          r.PostFormValue("disabled") == "on",
	}
	if t.Plan == "" {
		t.Plan = "free"
	}
	if err := s.Journal.UpsertTenant(r.Context(), t); err != nil {
		s.errorPage(w, "save tenant", err)
		return
	}
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}

// tenantsDelete removes an empty tenant (admin-only). The journal refuses
// deletion while users, workflows, credentials, runs, or other durable
// tenant-owned records remain, preserving quota and disabled-state policy.
func (s *Server) tenantsDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.Journal.DeleteTenant(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}

// atoiClampZero parses a non-negative int from a form field; blank, invalid,
// or negative all mean 0 (= unlimited).
func atoiClampZero(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func urlEsc(s string) string { return template.URLQueryEscaper(s) }

// fmtCompute renders billable compute seconds compactly (s / m / h).
func fmtCompute(secs float64) string {
	switch {
	case secs < 90:
		return fmt.Sprintf("%.0fs", secs)
	case secs < 5400:
		return fmt.Sprintf("%.1fm", secs/60)
	default:
		return fmt.Sprintf("%.1fh", secs/3600)
	}
}

// quotaLabel renders a quota: 0 means unlimited.
func quotaLabel(n int) string {
	if n <= 0 {
		return `<span class="muted">unlimited</span>`
	}
	return strconv.Itoa(n)
}

func tenantsBody(views []tenantView, plans []journal.Plan, errMsg string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err" style="background:#fff;border:1px solid var(--err);padding:12px 16px;margin:0 0 16px;border-radius:3px;">` +
			template.HTMLEscapeString(errMsg) + `</div>`)
	}
	b.WriteString(`<p class="muted">A tenant is a billing + isolation boundary. The fair-share claim interleaves tenants so one tenant's backlog cannot starve another, and a plan's caps bound how much each may consume. A quota of 0 means unlimited. Usage + bill are for the current calendar month; billable compute is active execution time, so suspended/waiting runs never count. Manage tiers on the <a href="/plans">Plans</a> page.</p>`)

	b.WriteString(`<table><thead><tr>` +
		`<th>Tenant</th><th>Plan</th><th>Status</th>` +
		`<th>Caps</th><th>This month</th><th>Est. bill</th><th></th>` +
		`</tr></thead><tbody>`)
	for _, v := range views {
		t := v.T
		status := `<span class="tag tag-on">active</span>`
		if t.Disabled {
			status = `<span class="tag tag-off">disabled</span>`
		}
		name := template.HTMLEscapeString(t.TenantID)
		if t.Name != "" {
			name += `<br><span class="muted">` + template.HTMLEscapeString(t.Name) + `</span>`
		}
		caps := fmt.Sprintf(`%s concurrent<br><span class="muted">%s queued / %s mo</span>`,
			quotaLabel(t.MaxConcurrentRuns), quotaLabel(t.MaxQueuedRuns), quotaLabel(t.MonthlyRunQuota))
		usage := fmt.Sprintf(`%d runs, %s compute<br><span class="muted">%d running / %d queued now</span>`,
			v.Usage.Runs, fmtCompute(v.Usage.ActiveSeconds), v.Running, v.Queued)
		bill := billCell(v.Bill)
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			name, planCell(t, plans), status, caps, usage, bill, tenantActions(t, plans),
		)
	}
	b.WriteString(`</tbody></table>`)

	b.WriteString(`<h2>Create or update tenant</h2>`)
	b.WriteString(`<p class="muted">Entering an existing tenant id updates it. The fastest path is to assign a plan (above), which sets the caps for you. New workflows inherit a tenant via their <code>tenant_id</code> column.</p>`)
	b.WriteString(`<form method="POST" action="/tenants" class="form">
  <label>Tenant id <input type="text" name="tenant_id" required autocomplete="off" placeholder="acme"></label>
  <label>Display name <input type="text" name="name" autocomplete="off" placeholder="Acme Inc"></label>
  <label>Plan label <input type="text" name="plan" autocomplete="off" placeholder="custom"></label>
  <label>Max concurrent runs (0 = unlimited) <input type="number" name="max_concurrent_runs" min="0" value="0"></label>
  <label>Max queued runs (0 = unlimited) <input type="number" name="max_queued_runs" min="0" value="0"></label>
  <label>Monthly run quota (0 = unlimited) <input type="number" name="monthly_run_quota" min="0" value="0"></label>
  <label class="form-inline"><input type="checkbox" name="hard_cap" checked> Hard cap (refuse past the monthly quota; leave off to allow overage)</label>
  <label class="form-inline"><input type="checkbox" name="disabled"> Disabled (refuse new runs)</label>
  <button type="submit" class="btn-primary">Save tenant</button>
</form>`)
	return b.String()
}

// planCell shows the tenant's current plan plus an inline assign dropdown.
func planCell(t journal.Tenant, plans []journal.Plan) string {
	var b strings.Builder
	cur := t.PlanID
	label := `<span class="muted">custom</span>`
	if cur != "" {
		label = `<code>` + template.HTMLEscapeString(cur) + `</code>`
	}
	b.WriteString(label)
	if len(plans) == 0 {
		return b.String()
	}
	fmt.Fprintf(&b, `<form method="POST" action="/tenants/%s/plan" class="form-inline" style="margin-top:4px;"><select name="plan_id">`, urlEsc(t.TenantID))
	for _, p := range plans {
		sel := ""
		if p.PlanID == cur {
			sel = " selected"
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`,
			template.HTMLEscapeString(p.PlanID), sel, template.HTMLEscapeString(p.PlanID))
	}
	b.WriteString(`</select> <button type="submit" class="btn-link">assign</button></form>`)
	return b.String()
}

// billCell shows the estimated current-period charge.
func billCell(bill journal.TenantBill) string {
	if bill.PlanID == "" {
		return `<span class="muted">no plan</span>`
	}
	out := `<strong>` + template.HTMLEscapeString(fmtMoney(bill.TotalCents, bill.Currency)) + `</strong>`
	if bill.OverageExecCents > 0 || bill.OverageComputeCents > 0 {
		out += fmt.Sprintf(`<br><span class="muted">base %s + overage %s</span>`,
			template.HTMLEscapeString(fmtMoney(bill.BasePriceCents, bill.Currency)),
			template.HTMLEscapeString(fmtMoney(bill.OverageExecCents+bill.OverageComputeCents, bill.Currency)))
	}
	return out
}

func tenantActions(t journal.Tenant, _ []journal.Plan) string {
	// GDPR: export (portability) + erase run data, available for every tenant.
	export := fmt.Sprintf(`<a href="/tenants/%s/export" class="btn-link" style="color:var(--accent);">export</a>`, urlEsc(t.TenantID))
	erase := fmt.Sprintf(`<form method="POST" action="/tenants/%s/erase" class="form-inline" data-confirm="Erase ALL run history + usage for tenant %s? This cannot be undone."><button type="submit" class="btn-link">erase data</button></form>`,
		urlEsc(t.TenantID), template.HTMLEscapeString(t.TenantID))
	if t.TenantID == "default" {
		return export + " " + erase + ` <span class="muted">(default)</span>`
	}
	del := fmt.Sprintf(`<form method="POST" action="/tenants/%s/delete" class="form-inline" data-confirm="Delete empty tenant %s? Tenants with users, workflows, credentials, runs, or other durable records must be cleaned up first."><button type="submit" class="btn-link">delete</button></form>`,
		urlEsc(t.TenantID), template.HTMLEscapeString(t.TenantID))
	return export + " " + erase + " " + del
}
