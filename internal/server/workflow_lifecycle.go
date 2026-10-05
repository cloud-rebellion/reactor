package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

// ManualDispatcher is the surface the dashboard's "Run now" button
// calls into. The daemon wires *dispatcher.Dispatcher which already
// has all the supervisor + binary + journal plumbing. Defined here
// so the server package doesn't import dispatcher (which would pull
// in supervisor + vault on read-only mounts).
type ManualDispatcher interface {
	// DispatchManual starts a live manual run and returns its id so the
	// dashboard can redirect to the run's live page.
	DispatchManual(ctx context.Context, t journal.Trigger, payload []byte) (string, error)
	// DispatchTest runs the workflow as a dry run (in-process, side effects
	// suppressed) for the dashboard's "test run".
	DispatchTest(ctx context.Context, t journal.Trigger, payload []byte) (string, error)
}

// RunCanceller stops an in-flight or suspended run. Returns one of the
// journal cancel outcomes ("cancelled" | "requested" | "not_cancellable").
// Defined here so the server package doesn't import dispatcher.
type RunCanceller interface {
	Cancel(ctx context.Context, runID string) (string, error)
}

// runCancel handles POST /runs/{id}/cancel. Cancels a running run (kills
// the subprocess) or a suspended run (stops the scheduler resuming it),
// then redirects back to the run detail page where the new status shows.
func (s *Server) runCancel(w http.ResponseWriter, r *http.Request) {
	if s.RunCanceller == nil {
		http.Error(w, "cancellation not wired on this deployment", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if !s.runInScope(r, id) {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	outcome, err := s.RunCanceller.Cancel(r.Context(), id)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "run not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "cancel run", err)
		return
	}
	if outcome == journal.CancelNotPossible {
		http.Error(w, "run is already finished; nothing to cancel", http.StatusConflict)
		return
	}
	// A suspended run terminates synchronously here (no live process), and
	// nothing else closes its log buffer, so flush it now to persist the
	// tail. A running run's buffer is closed by the dispatcher when the
	// killed subprocess reaches its terminal hook.
	if outcome == journal.CancelDone && s.LogBuffer != nil {
		s.LogBuffer.Close(id)
	}
	http.Redirect(w, r, "/runs/"+id, http.StatusSeeOther)
}

// workflowRun handles POST /workflows/{slug}/run. Body is form-encoded
// with a "payload" field carrying optional JSON. The handler builds a
// manual trigger + dispatches; the dashboard's run list page picks up
// the new row within a tick.
func (s *Server) workflowRun(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	payload := strings.TrimSpace(r.PostFormValue("payload"))
	if payload == "" {
		payload = "{}"
	}
	if !json.Valid([]byte(payload)) {
		http.Error(w, "payload must be valid JSON", http.StatusBadRequest)
		return
	}

	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
		s.errorPage(w, "lookup workflow", err)
		return
	}

	// Tenant isolation: a member may only dispatch their own tenant's
	// workflows. Slugs are unique per-tenant, not globally, so without this a
	// member could POST /workflows/{another-tenant-slug}/run and run it.
	if scope := viewerScope(r); scope != "" {
		if owner, oErr := s.Journal.WorkflowTenant(r.Context(), wfID); oErr == nil && owner != scope {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
	}

	if enabled, err := s.Journal.IsWorkflowEnabled(r.Context(), wfID); err == nil && !enabled {
		http.Error(w, "workflow is disabled; enable it before running", http.StatusConflict)
		return
	}

	trg := journal.Trigger{
		WorkflowID: wfID,
		Kind:       journal.TriggerManual,
		Config:     json.RawMessage(`{}`),
		State:      "active",
	}
	var runID string
	if r.PostFormValue("dry_run") == "on" {
		// Test run: execute in-process, suppress notifications + chains.
		runID, err = s.ManualDispatch.DispatchTest(r.Context(), trg, []byte(payload))
		if err != nil {
			s.errorPage(w, "dispatch test run", err)
			return
		}
	} else if runID, err = s.ManualDispatch.DispatchManual(r.Context(), trg, []byte(payload)); err != nil {
		s.errorPage(w, "dispatch manual run", err)
		return
	}
	// Land on the run's own page so the operator watches it stream live.
	// Fall back to the filtered run list if no id came back (shouldn't happen
	// for an enabled manual run, but a skipped dispatch returns "").
	if runID == "" {
		http.Redirect(w, r, "/runs?workflow_id="+template.URLQueryEscaper(wfID), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/runs/"+runID, http.StatusSeeOther)
}

// workflowEnable / workflowDisable / workflowDelete handle the
// operator-driven lifecycle that previously required dropping into
// SQL. Each redirects back to the workflow detail page (or /, for
// delete) so the operator sees the new state.
func (s *Server) workflowEnable(w http.ResponseWriter, r *http.Request) {
	s.setWorkflowEnabled(w, r, true)
}

func (s *Server) workflowDisable(w http.ResponseWriter, r *http.Request) {
	s.setWorkflowEnabled(w, r, false)
}

func (s *Server) setWorkflowEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		s.errorPage(w, "lookup workflow", err)
		return
	}
	var reviewedVersion journal.WorkflowVersion
	if enabled {
		version, versionErr := s.Journal.CurrentWorkflowVersionRecordBounded(r.Context(), wfID, maxFlowDAGBytes)
		if versionErr != nil {
			http.Error(w, "workflow cannot be enabled until an immutable reviewed version exists", http.StatusConflict)
			return
		}
		if version.DAGTruncated {
			http.Error(w, fmt.Sprintf("workflow cannot be enabled: recorded DAG is %d bytes and exceeds the bounded dashboard projection", version.DAGBytes), http.StatusConflict)
			return
		}
		reviewedVersion = version
		stateRoot := strings.TrimSpace(s.State)
		if stateRoot == "" && s.Registry != nil {
			stateRoot = filepath.Dir(s.Registry.Root)
		}
		tenantID, tenantErr := s.Journal.WorkflowTenant(r.Context(), wfID)
		if tenantErr != nil {
			http.Error(w, "workflow cannot be enabled: workflow tenant is unavailable", http.StatusConflict)
			return
		}
		// Activation is a new trust decision: a pre-existing artifact may be
		// allowed to finish/dispatch under its original source policy, but an
		// unverified legacy inner-step block graph must not pass review-to-enable.
		proof := workflowproof.CheckVersionForTenant(stateRoot, slug, tenantID, version)
		if proof.Status != "verified" {
			http.Error(w, "workflow cannot be enabled: "+proof.Error(), http.StatusConflict)
			return
		}
		if s.WorkerArtifactRoot != "" {
			workerProof := workflowproof.CheckVersionForTenant(s.WorkerArtifactRoot, slug, tenantID, version)
			if workerProof.Status != "verified" {
				http.Error(w, "workflow cannot be enabled: exact artifact and retained source are not verified on distributed worker storage (status "+workerProof.Status+"); publish the reviewed version first", http.StatusConflict)
				return
			}
		}
	}
	if enabled {
		// The proof above is a read-time check; fence the state mutation to the
		// exact immutable version that was reviewed so a concurrent authoring
		// write cannot activate a different version.
		if err := s.Journal.SetWorkflowEnabledIfVersion(r.Context(), wfID, true, reviewedVersion.Version); err != nil {
			s.errorPage(w, "set workflow enabled", err)
			return
		}
	} else if err := s.Journal.SetWorkflowEnabled(r.Context(), wfID, false); err != nil {
		s.errorPage(w, "set workflow enabled", err)
		return
	}
	http.Redirect(w, r, "/workflows/"+slug, http.StatusSeeOther)
}

func (s *Server) workflowDelete(w http.ResponseWriter, r *http.Request) {
	if s.Auth != nil && !requireAdmin(w, r) {
		return
	}
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		s.errorPage(w, "lookup workflow", err)
		return
	}
	if err := s.Journal.DeleteWorkflow(r.Context(), wfID); err != nil {
		if errors.Is(err, journal.ErrWorkflowBusy) {
			http.Error(w,
				"cannot delete: "+err.Error()+"; disable the workflow and wait for runs to finish first",
				http.StatusConflict)
			return
		}
		s.errorPage(w, "delete workflow", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// workflowSetMinutesSaved handles POST /workflows/{slug}/minutes-saved
// with an integer "minutes" form value. Powers the per-workflow time-
// saved baseline an operator declares on the workflow detail page;
// the home dashboard's headline "Time saved" tile multiplies this by
// the workflow's succeeded run count and sums across workflows.
func (s *Server) workflowSetMinutesSaved(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.PostFormValue("minutes"))
	minutes, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "minutes must be a non-negative integer", http.StatusBadRequest)
		return
	}
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
		s.errorPage(w, "lookup workflow", err)
		return
	}
	if err := s.Journal.SetEstimatedMinutesSavedPerRun(r.Context(), wfID, minutes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/workflows/"+slug, http.StatusSeeOther)
}

// workflowSetRateLimit handles POST /workflows/{slug}/rate-limit, setting the
// workflow's max runs per minute (0 = unlimited).
func (s *Server) workflowSetRateLimit(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	perMin, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("per_min")))
	if err != nil || perMin < 0 {
		http.Error(w, "per_min must be a non-negative integer", http.StatusBadRequest)
		return
	}
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
		s.errorPage(w, "lookup workflow", err)
		return
	}
	if err := s.Journal.SetWorkflowRateLimit(r.Context(), wfID, perMin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/workflows/"+slug, http.StatusSeeOther)
}

// triggerPause / triggerResume flip the triggers.state column. The
// cron driver's polling reconcile picks up the change within 30s and
// removes / re-adds the robfig entry as needed. Webhook triggers stop
// dispatching on first request to /webhook/{token} after the flip.
func (s *Server) triggerPause(w http.ResponseWriter, r *http.Request) {
	s.setTriggerState(w, r, "disabled")
}

func (s *Server) triggerResume(w http.ResponseWriter, r *http.Request) {
	s.setTriggerState(w, r, "active")
}

func (s *Server) setTriggerState(w http.ResponseWriter, r *http.Request, state string) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
		s.errorPage(w, "lookup workflow", err)
		return
	}
	triggerID := chi.URLParam(r, "trigger_id")
	if err := s.Journal.SetTriggerStateForWorkflow(r.Context(), triggerID, wfID, state); err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "trigger not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "set trigger state", err)
		return
	}
	http.Redirect(w, r, workflowHrefFromRequest(r, slug), http.StatusSeeOther)
}

// triggerEditCron handles POST /workflows/{slug}/triggers/{trigger_id}/edit
// with new cron spec + timezone. Only cron triggers are editable
// today (webhook tokens are immutable by design so URLs don't rot).
func (s *Server) triggerEditCron(w http.ResponseWriter, r *http.Request) {
	slug, ok := slugFromRequest(w, r)
	if !ok {
		return
	}
	wfID, err := s.workflowIDForViewer(r, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "workflow not registered", http.StatusNotFound)
			return
		}
		s.errorPage(w, "lookup workflow", err)
		return
	}
	triggerID := chi.URLParam(r, "trigger_id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	spec := strings.TrimSpace(r.PostFormValue("spec"))
	timezone := strings.TrimSpace(r.PostFormValue("timezone"))
	if spec == "" {
		http.Error(w, "spec is required", http.StatusBadRequest)
		return
	}
	cfgMap := map[string]string{"spec": spec}
	if timezone != "" {
		cfgMap["timezone"] = timezone
	}
	cfg, _ := json.Marshal(cfgMap)
	if err := s.Journal.UpdateCronTriggerConfigForWorkflow(r.Context(), triggerID, wfID, cfg); err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			http.Error(w, "cron trigger not found", http.StatusNotFound)
			return
		}
		s.errorPage(w, "update trigger config", err)
		return
	}
	http.Redirect(w, r, workflowHrefFromRequest(r, slug), http.StatusSeeOther)
}

// credentialUpdateValue handles POST /credentials/{id}/value with a
// new plaintext value. Re-encrypts in the vault + writes a
// "rotate.manual.dashboard" audit row + bumps last_rotated_at via
// MarkRotated. Use this when an operator has a new value from
// upstream (e.g. they regenerated the Stripe key on the Stripe
// dashboard) and want to swap in reactor.
func (s *Server) credentialUpdateValue(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	value := r.PostFormValue("value")
	if value == "" {
		http.Error(w, "value is required", http.StatusBadRequest)
		return
	}
	if err := s.Vault.Rotate(r.Context(), id, []byte(value)); err != nil {
		s.errorPage(w, "vault rotate", err)
		return
	}
	now := nowForAudit()
	if err := s.Credentials.MarkRotated(r.Context(), id, now); err != nil {
		s.Log.Warn("server: mark rotated after manual update failed", "credential_id", id, "err", err)
	}
	_ = s.Credentials.AppendAudit(r.Context(), credentials.AuditEntry{
		CredentialID: id,
		Action:       "rotate.manual.dashboard",
		ActorKind:    "operator",
	})
	http.Redirect(w, r, "/credentials/"+id, http.StatusSeeOther)
}

func nowForAudit() (t time.Time) {
	return time.Now().UTC()
}
