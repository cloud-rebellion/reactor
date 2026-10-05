package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/catalog"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// catLabel is the human label for a catalog category in the UI.
func catLabel(cat string) string {
	switch cat {
	case "crm":
		return "CRM"
	case "project-management":
		return "Project management"
	case "cms":
		return "CMS"
	case "payments":
		return "Payments"
	case "email":
		return "Email"
	case "dev":
		return "Developer"
	default:
		return cat
	}
}

// credentialNewForm renders the form an operator fills in to add a new
// credential through the UI. The CLI surface (`reactor vault add`) still
// works; this is for non-dev tenants who never want to open a terminal.
func (s *Server) credentialNewForm(w http.ResponseWriter, r *http.Request) {
	tenants, current := s.availableTenants(r)
	s.renderPage(w, r, page{
		Title:   "New credential",
		Heading: "New credential",
		Body:    template.HTML(credentialNewBody("", tenants, current)),
	})
}

// credentialCreate handles POST /credentials. Body is application/x-www-
// form-urlencoded with the same fields as `reactor vault add`. On success
// the row + encrypted vault blob land atomically; the dashboard redirects
// to the detail page.
// credentialTargetAdd appends a rotation delivery target.
//
// Rotation's whole point is that consumers get the new value without a restart,
// and rotation_targets was reachable ONLY through hand-written SQL: no repo
// setter, no caller, no UI, no CLI flag. Every credential an operator could
// create therefore had zero targets, so a rotated value was stored and delivered
// nowhere while the audit trail recorded success.
func (s *Server) credentialTargetAdd(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	c, err := s.Credentials.Get(r.Context(), id)
	if err != nil {
		s.errorPage(w, "get credential", err)
		return
	}
	grace := 0
	if v := strings.TrimSpace(r.PostFormValue("grace_seconds")); v != "" {
		n, cerr := strconv.Atoi(v)
		if cerr != nil || n < 0 {
			s.redirectWithTargetError(w, r, id, "grace seconds must be a non-negative whole number")
			return
		}
		grace = n
	}
	t := credentials.Target{
		Kind:         strings.TrimSpace(r.PostFormValue("kind")),
		URL:          strings.TrimSpace(r.PostFormValue("url")),
		KeyName:      strings.TrimSpace(r.PostFormValue("key_name")),
		SecretID:     strings.TrimSpace(r.PostFormValue("secret_id")),
		GraceSeconds: grace,
	}
	// Validate here rather than at rotation time, which would surface hours
	// later inside a scheduler tick nobody is watching.
	if verr := t.Validate(); verr != nil {
		s.redirectWithTargetError(w, r, id, verr.Error())
		return
	}
	if serr := s.Credentials.SetRotationTargets(r.Context(), id, append(c.RotationTargets, t)); serr != nil {
		s.redirectWithTargetError(w, r, id, serr.Error())
		return
	}
	_ = s.Credentials.AppendAudit(r.Context(), credentials.AuditEntry{
		CredentialID: id,
		Action:       "target.add",
		ActorKind:    "operator",
	})
	s.redirectWithTargetError(w, r, id, "")
}

// credentialTargetDelete removes one target by its position in the list.
func (s *Server) credentialTargetDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	idx, err := strconv.Atoi(chi.URLParam(r, "index"))
	if id == "" || err != nil || idx < 0 {
		http.Error(w, "missing id or index", http.StatusBadRequest)
		return
	}
	c, gerr := s.Credentials.Get(r.Context(), id)
	if gerr != nil {
		s.errorPage(w, "get credential", gerr)
		return
	}
	if idx >= len(c.RotationTargets) {
		s.redirectWithTargetError(w, r, id, "that target no longer exists; the list may have changed since the page was loaded")
		return
	}
	remaining := append(append([]credentials.Target{}, c.RotationTargets[:idx]...), c.RotationTargets[idx+1:]...)
	if serr := s.Credentials.SetRotationTargets(r.Context(), id, remaining); serr != nil {
		s.redirectWithTargetError(w, r, id, serr.Error())
		return
	}
	_ = s.Credentials.AppendAudit(r.Context(), credentials.AuditEntry{
		CredentialID: id,
		Action:       "target.remove",
		ActorKind:    "operator",
	})
	s.redirectWithTargetError(w, r, id, "")
}

// redirectWithTargetError carries a message back to the detail page through the
// flash store. A bare 303 with no message is how "Rotate now" managed to look
// identical whether it worked or did nothing.
func (s *Server) redirectWithTargetError(w http.ResponseWriter, r *http.Request, id, msg string) {
	if msg != "" && s.flash != nil {
		if err := s.flash.put(w, r, map[string]string{"rotate_outcome": msg}); err != nil {
			s.Log.Warn("target: flash put failed", "err", err, "credential_id", id)
		}
	}
	http.Redirect(w, r, "/credentials/"+id, http.StatusSeeOther)
}

// credentialDelete soft-deletes a credential and removes its vault blob.
//
// There was no delete route at all, and because `UNIQUE (tenant_id, name)` also
// covered soft-deleted rows, a name was consumed permanently. Migration 0025
// scopes that uniqueness to live rows; this is the surface that uses it.
//
// The row survives as a tombstone on purpose: credential_audit holds an
// ON DELETE-less FK to it, and dropping the audit trail to free a name is the
// wrong trade for a security product.
func (s *Server) credentialDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	// Refuse while workflows still hold a grant. Deleting underneath them would
	// turn every future secret fetch into a silent runtime failure, which is
	// exactly the class of "succeeds now, breaks later" this audit kept finding.
	if s.Journal != nil {
		if granted := s.workflowsGrantedAccess(r.Context(), id); len(granted) > 0 {
			s.redirectWithTargetError(w, r, id, fmt.Sprintf(
				"still granted to %d workflow(s): %s. Revoke those grants first, or their next secret fetch fails at runtime with no warning.",
				len(granted), strings.Join(granted, ", ")))
			return
		}
	}
	retained := false
	if err := s.Credentials.Delete(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, credentials.ErrNotFound):
			http.Error(w, "credential not found", http.StatusNotFound)
			return
		case errors.Is(err, credentials.ErrAuditRetained):
			retained = true
		default:
			s.errorPage(w, "delete credential", err)
			return
		}
	}
	// Drop the secret itself. Best-effort: the row is already tombstoned, so a
	// vault failure must not leave the operator unable to proceed, but it is
	// logged because a lingering blob is a real (if inert) secret at rest.
	if s.Vault != nil {
		if err := s.Vault.Delete(r.Context(), id); err != nil {
			s.Log.Warn("credential delete: vault blob remains", "err", err, "credential_id", id)
		}
	}
	// Appending this audit row is itself what forces a credential deleted twice
	// to stay a tombstone, which is the correct trade: the trail outlives the
	// secret.
	_ = s.Credentials.AppendAudit(r.Context(), credentials.AuditEntry{
		CredentialID: id,
		Action:       "delete.dashboard",
		ActorKind:    "operator",
	})
	if retained && s.flash != nil {
		// Say plainly that the identifier is NOT reusable, rather than letting
		// the operator discover it from a duplicate-key error on the next create.
		if err := s.flash.put(w, r, map[string]string{"rotate_outcome": fmt.Sprintf(
			"Deleted %q and removed its secret. The row is kept because it has audit history, so that name stays reserved: reuse it by picking a different name, or accept the tombstone.", id)}); err != nil {
			s.Log.Warn("credential delete: flash put failed", "err", err, "credential_id", id)
		}
	}
	http.Redirect(w, r, "/credentials", http.StatusSeeOther)
}

// rotationGuard refuses the two provider/auto-rotate combinations that silently
// do the wrong thing, returning the operator-facing reason or "" when the
// combination is sound. Kept separate from the handler so the rule is testable
// without an HTTP request or a wired repo.
//
// The first is destruction, not a mismatch: shared-secret used to be the FIRST
// <option> and therefore the default, and it MINTS a new random value locally.
// An operator adding a real Stripe key with the select untouched, then clicking
// "Rotate now", had the sk_live_ key overwritten with random hex while the audit
// trail recorded rotate.success and Stripe still held the old key. Payments
// break silently and the original is unrecoverable.
func (s *Server) rotationGuard(provider string, autoRotate, ackReplace bool) string {
	if s.Rotator == nil {
		return ""
	}
	canAuto, mintsLocally, err := s.Rotator.ProviderCapabilities(provider)
	switch {
	case err != nil:
		return "unknown provider " + provider
	case mintsLocally && !ackReplace:
		return "provider \"" + provider + "\" REPLACES the stored value with a newly generated random secret on every rotation. That is correct only for a secret Reactor itself issues (an HMAC signing key where Reactor controls both ends). For a key issued by another service it would overwrite the real key with a value that service has never seen, and the integration would break with no warning. Choose \"manual\" for an externally issued key, or tick the acknowledgement to proceed."
	case autoRotate && !canAuto:
		return "provider \"" + provider + "\" cannot rotate automatically, so Auto-rotate would only ever record a reminder and the value would never change. Untick Auto-rotate, or pick a provider that rolls the credential at its source."
	}
	return ""
}

func (s *Server) credentialCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	service := strings.TrimSpace(r.PostFormValue("service"))
	provider := strings.TrimSpace(r.PostFormValue("provider"))
	value := r.PostFormValue("value")
	autoRotate := r.PostFormValue("auto_rotate") == "on"
	intervalDaysStr := strings.TrimSpace(r.PostFormValue("interval_days"))

	if name == "" || provider == "" || value == "" {
		s.renderCredentialNewError(w, r, "name, provider, and value are required", name, service)
		return
	}
	intervalDays := 0
	if intervalDaysStr != "" {
		n, err := strconv.Atoi(intervalDaysStr)
		if err != nil || n < 0 {
			s.renderCredentialNewError(w, r, "interval_days must be a non-negative integer", name, service)
			return
		}
		intervalDays = n
	}

	// Guard the two combinations that silently do the wrong thing.
	//
	// The default used to be shared-secret purely because it was the first
	// <option>, and it MINTS a new random value locally. An operator adding a
	// Stripe key with the select untouched, then clicking "Rotate now", had the
	// real sk_live_ key overwritten with random hex while the audit trail
	// recorded rotate.success and Stripe still held the old key. Payments break
	// silently, and there is no way back because the original is gone.
	if reason := s.rotationGuard(provider, autoRotate, r.PostFormValue("confirm_replace") == "on"); reason != "" {
		s.renderCredentialNewError(w, r, reason, name, service)
		return
	}

	// Owning tenant. A SCOPED viewer (a member) is forced into their own tenant
	// whatever the form says, so a crafted POST cannot plant a credential in
	// someone else's tenant; only a global admin may choose.
	tenantID := strings.TrimSpace(r.PostFormValue("tenant_id"))
	if scope := viewerScope(r); scope != "" {
		tenantID = scope
	}
	if tenantID == "" {
		tenantID = journal.DefaultTenant
	}

	id := name
	if err := s.Credentials.Create(r.Context(), credentials.CreateParams{
		TenantID:             tenantID,
		ID:                   id,
		Name:                 name,
		Service:              service,
		Provider:             provider,
		AllowLocalMint:       r.PostFormValue("confirm_replace") == "on",
		AutoRotate:           autoRotate,
		RotationIntervalDays: intervalDays,
	}); err != nil {
		s.renderCredentialNewError(w, r, "create credential: "+err.Error(), name, service)
		return
	}
	if err := s.Vault.Put(r.Context(), id, []byte(value)); err != nil {
		// Roll the row back. Without this the create leaves a credential with no
		// secret that cannot be deleted (credential_audit's FK refuses a hard
		// delete once any audit row exists) and whose name can never be reused,
		// a state an operator could only escape with hand-written SQL.
		// Reproduced on a live instance: a wrong master key is enough to hit it.
		if derr := s.Credentials.Delete(r.Context(), id); derr != nil {
			s.Log.Warn("credential create: rollback failed, orphan row remains",
				"err", derr, "credential_id", id)
		}
		s.renderCredentialNewError(w, r, "vault put: "+err.Error(), name, service)
		return
	}
	_ = s.Credentials.AppendAudit(r.Context(), credentials.AuditEntry{
		CredentialID: id,
		Action:       "create.dashboard",
		ActorKind:    "operator",
	})
	http.Redirect(w, r, "/credentials/"+id, http.StatusSeeOther)
}

func (s *Server) renderCredentialNewError(w http.ResponseWriter, r *http.Request, msg, name, service string) {
	tenants, current := s.availableTenants(r)
	w.WriteHeader(http.StatusUnprocessableEntity)
	render(w, layout, page{
		Title:   "New credential",
		Heading: "New credential",
		Body:    template.HTML(credentialNewBody(msg, tenants, current)) + template.HTML(`<input type="hidden" id="prefill-name" value="`+template.HTMLEscapeString(name)+`"><input type="hidden" id="prefill-service" value="`+template.HTMLEscapeString(service)+`">`),
	})
}

// credentialRotate handles POST /credentials/{id}/rotate. Drives the
// rotator's per-credential pipeline (mint -> encrypt -> persist ->
// deliver to targets -> audit) and redirects back to the detail page.
// The audit row + last_rotated_at update tell the operator what
// happened on the next render.
func (s *Server) credentialRotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	// Resolve the provider BEFORE rotating so the outcome can be reported. A
	// reminder-only provider (manual, which service-presets.js selects for every
	// catalog API-key service) makes RotateOne write an audit row and return
	// nil, and this handler used to 303 straight back with NO message at all.
	// So the product's headline button did nothing observable on its most common
	// configuration, and an operator could not tell that from a real rotation.
	var outcome string
	allowLocalMint := r.PostFormValue("allow_local_mint") == "on"
	localMint := false
	if c, cerr := s.Credentials.Get(r.Context(), id); cerr == nil {
		if canAuto, mintsLocally, perr := s.Rotator.ProviderCapabilities(c.Provider); perr == nil {
			localMint = mintsLocally
			if mintsLocally && !allowLocalMint {
				s.errorPage(w, "rotate", fmt.Errorf("provider %q generates replacement values locally; tick the acknowledgement before rotating", c.Provider))
				return
			}
			if !canAuto {
				outcome = "Recorded a rotation reminder. Provider \"" + c.Provider +
					"\" cannot roll this credential programmatically, so the stored value is unchanged: rotate it at the issuing service, then paste the new value into \"Update value\" below."
			}
		}
	}
	var rotateErr error
	if localMint {
		if ackRotator, ok := s.Rotator.(interface {
			RotateOneWithLocalMintAck(context.Context, string, bool) error
		}); ok {
			rotateErr = ackRotator.RotateOneWithLocalMintAck(r.Context(), id, allowLocalMint)
		} else {
			rotateErr = errors.New("rotation provider does not expose the local-mint acknowledgement boundary")
		}
	} else {
		rotateErr = s.Rotator.RotateOne(r.Context(), id)
	}
	if rotateErr != nil {
		s.errorPage(w, "rotate", rotateErr)
		return
	}
	if outcome == "" {
		outcome = "Rotation ran. Check the audit trail below for the delivery result of each target; a credential with no rotation targets is stored but delivered nowhere."
	}
	if err := s.flash.put(w, r, map[string]string{"rotate_outcome": outcome}); err != nil {
		s.Log.Warn("rotate: flash put failed", "err", err, "credential_id", id)
	}
	http.Redirect(w, r, "/credentials/"+id, http.StatusSeeOther)
}

// credentialGrant handles POST /credentials/{id}/grants with a
// workflow_id form field. Idempotent (Journal.GrantSecret does
// ON CONFLICT UPDATE) so repeated submits don't error.
func (s *Server) credentialGrant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	wf := strings.TrimSpace(r.PostFormValue("workflow_id"))
	if wf == "" {
		http.Error(w, "workflow_id required", http.StatusBadRequest)
		return
	}
	// Accept a slug too; resolve to id if the table knows it.
	if wfID, err := s.workflowIDForViewer(r, wf); err == nil && wfID != "" {
		wf = wfID
	}
	if err := s.Journal.GrantSecret(r.Context(), wf, id, "dashboard", ""); err != nil {
		s.errorPage(w, "grant secret", err)
		return
	}
	_ = s.Credentials.AppendAudit(r.Context(), credentials.AuditEntry{
		CredentialID: id,
		Action:       "grant.dashboard",
		ActorKind:    "operator",
		WorkflowID:   wf,
	})
	http.Redirect(w, r, "/credentials/"+id, http.StatusSeeOther)
}

// credentialRevoke handles POST /credentials/{id}/grants/{workflow_id}/revoke.
// Errors via 404 if the grant didn't exist (idempotent operators get a
// readable page rather than a silent 200).
func (s *Server) credentialRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	wf := chi.URLParam(r, "workflow_id")
	// Mirror credentialGrant: the revoke URL may carry a slug from the
	// rendered detail page (WorkflowSlugByID resolves wf_id -> slug),
	// so resolve back to wf_id before the DELETE.
	if wfID, err := s.workflowIDForViewer(r, wf); err == nil && wfID != "" {
		wf = wfID
	}
	if err := s.Journal.RevokeSecret(r.Context(), wf, id); err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, fmt.Sprintf("no grant for workflow %s on credential %s", wf, id), http.StatusNotFound)
			return
		}
		s.errorPage(w, "revoke secret", err)
		return
	}
	_ = s.Credentials.AppendAudit(r.Context(), credentials.AuditEntry{
		CredentialID: id,
		Action:       "revoke.dashboard",
		ActorKind:    "operator",
		WorkflowID:   wf,
	})
	http.Redirect(w, r, "/credentials/"+id, http.StatusSeeOther)
}

// credentialNewBody renders the add-credential form. errMsg is shown
// inline above the fields when non-empty.
// tenantSelect renders the owning-tenant picker for a create form, or nothing
// when there is only one tenant to choose from.
//
// Without it the tenant plumbing is unreachable: an admin is global (viewerScope
// returns ""), so even once the writers accept a tenant there is no way through
// the UI to say which one, and everything keeps landing in "default". A member
// sees their own tenant as read-only text, because the server forces their scope
// regardless of what the form submits.
func tenantSelect(tenants []journal.Tenant, current string) string {
	if current == "" {
		current = journal.DefaultTenant
	}
	if len(tenants) < 2 {
		// Nothing to choose. Still submit the value so the create path is
		// explicit about ownership rather than relying on a column default.
		return `<input type="hidden" name="tenant_id" value="` + template.HTMLEscapeString(current) + `">`
	}
	var b strings.Builder
	b.WriteString(`<label>Owning tenant <select name="tenant_id">`)
	for _, t := range tenants {
		sel := ""
		if t.TenantID == current {
			sel = " selected"
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`,
			template.HTMLEscapeString(t.TenantID), sel, template.HTMLEscapeString(t.TenantID))
	}
	b.WriteString(`</select></label>`)
	return b.String()
}

// availableTenants lists the tenants the viewer may create in. A scoped member
// gets exactly their own; an admin gets all of them.
func (s *Server) availableTenants(r *http.Request) ([]journal.Tenant, string) {
	current := viewerTenant(r)
	if scope := viewerScope(r); scope != "" || s.Journal == nil {
		return []journal.Tenant{{TenantID: current}}, current
	}
	list, err := s.Journal.ListTenants(r.Context())
	if err != nil || len(list) == 0 {
		return []journal.Tenant{{TenantID: current}}, current
	}
	return list, current
}

func credentialNewBody(errMsg string, tenants []journal.Tenant, currentTenant string) string {
	var b strings.Builder
	if errMsg != "" {
		b.WriteString(`<div class="err">` + template.HTMLEscapeString(errMsg) + `</div>`)
	}
	// Catalog quick-add: pick a known service to pre-fill its suggested vault
	// key name + where to get the key. service-presets.js fills the form below.
	b.WriteString(`<h3>Quick-add a service</h3><p class="muted">Pick a service to pre-fill its key name and where to find the key, then paste your key into the form.</p>`)
	b.WriteString(`<div class="svc-presets">`)
	lastCat := ""
	for _, svc := range catalog.APIKeyServices() {
		if svc.Category != lastCat {
			b.WriteString(`<span class="svc-cat">` + template.HTMLEscapeString(catLabel(svc.Category)) + `</span>`)
			lastCat = svc.Category
		}
		hint := svc.KeyHint + " | " + svc.AuthScheme + " | Docs: " + svc.Docs
		fmt.Fprintf(&b, `<button type="button" class="svc-preset" data-key-name="%s" data-service="%s" data-hint="%s">%s</button>`,
			template.HTMLEscapeString(svc.KeyName), template.HTMLEscapeString(svc.ID),
			template.HTMLEscapeString(hint), template.HTMLEscapeString(svc.Name))
	}
	b.WriteString(`</div><p id="svc-preset-note" class="muted oauth-preset-note"></p>`)

	b.WriteString(`
<form method="POST" action="/credentials" class="form" id="credential-form">
  <p class="muted">Adds a credential to the vault. Encrypted on write. The plaintext value is read-only after submission; rotate it later via the "Rotate now" button on the detail page.</p>
  <label>Name <input type="text" name="name" required pattern="[a-z0-9_\-]+" title="lowercase letters, digits, underscore, hyphen" autocomplete="off"></label>
  <label>Service <input type="text" name="service" placeholder="e.g. stripe, sendgrid" autocomplete="off"></label>` +
		tenantSelect(tenants, currentTenant) + `
  <label>Provider
    <select name="provider" required>
      <option value="manual">manual -- Reactor never changes the value; rotating records a reminder only. Correct for every externally issued API key (Stripe, Slack, SendGrid, ...)</option>
      <option value="cloudflare">cloudflare -- rolls the token AT Cloudflare and stores the new one</option>
      <option value="aws-iam">aws-iam -- rolls the access key pair AT AWS and stores the new one</option>
      <option value="shared-secret">shared-secret -- REPLACES the value with a new random secret. Only for a secret Reactor itself issues, e.g. an HMAC signing key</option>
    </select>
  </label>
  <label>Value <input type="password" name="value" required autocomplete="new-password" placeholder="initial plaintext, encrypted on write"></label>
  <label class="inline"><input type="checkbox" name="confirm_replace"> I understand <code>shared-secret</code> replaces the stored value with a newly generated random secret (only needed for that provider)</label>
  <label class="inline"><input type="checkbox" name="auto_rotate"> Auto-rotate</label>
  <label>Rotation interval (days, 0 = no schedule) <input type="number" name="interval_days" min="0" value="0"></label>
  <button type="submit">Create</button>
  <a href="/credentials" class="btn-secondary">Cancel</a>
</form>
<script src="/assets/service-presets.js"></script>
`)
	return b.String()
}
