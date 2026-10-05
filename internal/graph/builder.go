package graph

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Builder reads from the journal + credentials repo + knowledge store
// and produces a freshly-rebuilt Graph. Used by the daemon at startup
// and by the dispatcher's CRUD hook for incremental updates.
type Builder struct {
	Journal     *journal.Journal
	Credentials *credentials.Repo
	Knowledge   *knowledge.Store

	// RecentRunLimit caps how many recent runs become run nodes. Default 50.
	RecentRunLimit int

	// JournalPageSize bounds each estate-wide journal read during a rebuild.
	// It does not cap the resulting graph: the builder still walks every page.
	// A bounded read keeps a large tenant estate from being materialised in a
	// second temporary slice by database/sql. Values <= 0 use the default.
	JournalPageSize int
}

const defaultJournalPageSize = 500

// Build returns a fully-populated Graph from a snapshot of the data.
// Concurrency: the Graph returned is owned by the caller; the journal
// + credentials reads are point-in-time, so a builder run that races
// with a write may miss the new row but won't corrupt anything.
func (b *Builder) Build(ctx context.Context) (*Graph, error) {
	g := New()
	if b == nil {
		return g, nil
	}

	recentRunLimit := b.RecentRunLimit
	if recentRunLimit <= 0 {
		recentRunLimit = 50
	}
	pageSize := b.JournalPageSize
	if pageSize <= 0 {
		pageSize = defaultJournalPageSize
	}
	// Command automation pagination currently accepts at most 500 rows. Keep
	// all graph inventory pages at that same bounded size so one setting cannot
	// accidentally turn a rebuild into a giant SQL result.
	if pageSize > defaultJournalPageSize {
		pageSize = defaultJournalPageSize
	}

	// Workflows + their direct outbound edges.
	if b.Journal != nil {
		workflowNodeIDs := make(map[string]string)
		workflowTenants := make(map[string]string)
		// Credential references in a command definition are untrusted IDs. Do
		// not turn an ID into a graph edge unless the metadata lookup proves
		// that the credential exists and is owned by the same tenant as the
		// plan. A global graph is later filtered by tenant, but emitting a
		// cross-tenant edge here would still make the topology claim a
		// relationship that the command authoring and grant gates reject.
		credentialTenants := make(map[string]string)
		credentialTenantLookups := make(map[string]bool)
		if b.Credentials != nil {
			for offset := 0; ; {
				creds, more, err := b.Credentials.ListMetadataPage(ctx, pageSize, offset)
				if err != nil {
					// Unknown ownership is fail-closed. The journal lookup below may
					// still prove an individual OAuth or legacy credential, but a
					// failed inventory must never make every id look owned.
					break
				}
				for _, c := range creds {
					tenant := c.TenantID
					if tenant == "" {
						tenant = credentials.DefaultTenant
					}
					credentialTenants[c.ID] = tenant
				}
				if !more || len(creds) == 0 {
					break
				}
				offset += len(creds)
			}
		}
		for offset := 0; ; {
			wfs, more, err := b.Journal.ListWorkflowsPage(ctx, pageSize, offset)
			if err != nil {
				return nil, fmt.Errorf("graph: list workflows: %w", err)
			}
			for _, wf := range wfs {
				nodeID := workflowNodeID(wf)
				workflowNodeIDs[wf.ID] = nodeID
				workflowTenant := wf.TenantID
				if workflowTenant == "" {
					workflowTenant = journal.DefaultTenant
				}
				workflowTenants[wf.ID] = workflowTenant
				g.AddNode(Node{
					ID:    nodeID,
					Kind:  KindWorkflow,
					Label: wf.Slug,
					Attrs: map[string]any{
						"id":          wf.ID,
						"tenant_id":   wf.TenantID,
						"sdk_version": wf.SDKVersion,
						"enabled":     wf.Enabled,
						"updated_at":  wf.UpdatedAt.UTC().Format(time.RFC3339),
					},
				})
			}
			if !more || len(wfs) == 0 {
				break
			}
			offset += len(wfs)
		}

		// Declarative command automations are reviewable graph nodes. Execution
		// is represented only through separate receipt-bound schedule/run paths;
		// only same-tenant credential references are shown on the plan node.
		for offset := 0; ; {
			plans, more, err := b.Journal.ListAllCommandAutomationsPage(ctx, pageSize, offset)
			if err != nil {
				// Older databases may be inspected before their latest migration;
				// keep graph startup best-effort like trigger and DLQ inventory.
				break
			}
			for _, plan := range plans {
				nodeID := commandAutomationNodeID(plan)
				g.AddNode(Node{
					ID: nodeID, Kind: KindCommandAutomation, Label: plan.Name,
					Attrs: map[string]any{
						"id": plan.ID, "tenant_id": plan.TenantID, "description": plan.Description,
						"target": plan.Target, "enabled": plan.Enabled, "current_version": plan.CurrentVersion,
						"updated_at":    plan.UpdatedAt.UTC().Format(time.RFC3339),
						"executable":    false,
						"content_trust": "untrusted",
					},
				})
				version, versionErr := b.Journal.GetCommandAutomationVersion(ctx, plan.TenantID, plan.ID, plan.CurrentVersion)
				if versionErr != nil {
					continue
				}
				definition, _, normalizeErr := commandautomations.Normalize(version.DefinitionJSON)
				if normalizeErr != nil {
					// Imported or legacy definitions are untrusted data. Do not
					// derive credential edges from a malformed plan, because that
					// would make the environment graph claim relationships the
					// authoring validator would reject.
					continue
				}
				for _, step := range definition.Steps {
					for _, credentialID := range step.CredentialIDs {
						credentialTenant, known := resolveGraphCredentialTenant(ctx, b.Journal, credentialTenants, credentialTenantLookups, credentialID)
						planTenant := plan.TenantID
						if planTenant == "" {
							planTenant = journal.DefaultTenant
						}
						if !known || credentialTenant != planTenant {
							continue
						}
						g.AddEdge(Edge{From: nodeID, To: KindCredential + ":" + credentialID, Kind: EdgeUses, Attrs: map[string]any{"step": step.Name}})
					}
				}
				// Command schedules are a separate trigger surface from workflow
				// triggers. Include only tenant-fenced metadata so the visual graph
				// shows how an unattended fire reaches this exact plan without
				// importing command text, credentials, or error payloads.
				planTenant := plan.TenantID
				if planTenant == "" {
					planTenant = journal.DefaultTenant
				}
				for scheduleOffset := 0; ; {
					schedules, scheduleMore, scheduleErr := b.Journal.ListCommandAutomationSchedulesForTenantPage(ctx, journal.CommandAutomationScheduleFilter{
						TenantID: planTenant, AutomationID: plan.ID, Limit: pageSize, Offset: scheduleOffset,
					})
					if scheduleErr != nil {
						break
					}
					for _, schedule := range schedules {
						scheduleNodeID := commandAutomationScheduleNodeID(schedule)
						attrs := map[string]any{
							"id": schedule.ID, "tenant_id": schedule.TenantID, "automation_id": schedule.AutomationID,
							"automation_version": schedule.AutomationVersion, "spec": schedule.Spec,
							"timezone": schedule.Timezone, "state": schedule.State, "revision": schedule.Revision,
							"content_trust": "metadata",
						}
						if schedule.LastFiredAt != nil && !schedule.LastFiredAt.IsZero() {
							attrs["last_fired_at"] = schedule.LastFiredAt.UTC().Format(time.RFC3339)
						}
						g.AddNode(Node{ID: scheduleNodeID, Kind: KindCommandSchedule, Label: schedule.Spec, Attrs: attrs})
						g.AddEdge(Edge{From: scheduleNodeID, To: nodeID, Kind: EdgeFires})
					}
					if !scheduleMore || len(schedules) == 0 {
						break
					}
					scheduleOffset += len(schedules)
				}

				// Command webhooks are a separate ingress surface from workflow
				// webhooks. Render only the tenant-fenced, reviewable binding
				// metadata; token IDs, secret references, request bodies, and raw
				// operational errors must never become graph attributes.
				for webhookOffset := 0; ; {
					webhooks, webhookMore, webhookErr := b.Journal.ListCommandAutomationWebhookTriggersForTenantPage(ctx, journal.CommandAutomationWebhookTriggerFilter{
						TenantID: planTenant, AutomationID: plan.ID, Limit: pageSize, Offset: webhookOffset,
					})
					if webhookErr != nil {
						break
					}
					for _, webhook := range webhooks {
						webhookNodeID := commandAutomationWebhookNodeID(webhook)
						attrs := map[string]any{
							"id": webhook.ID, "tenant_id": webhook.TenantID, "automation_id": webhook.AutomationID,
							"automation_version": webhook.AutomationVersion, "provider": webhook.Provider,
							"state": webhook.State, "revision": webhook.Revision, "content_trust": "metadata",
						}
						if webhook.LastFiredAt != nil && !webhook.LastFiredAt.IsZero() {
							attrs["last_fired_at"] = webhook.LastFiredAt.UTC().Format(time.RFC3339)
						}
						if webhook.LastError != "" {
							attrs["last_error_present"] = true
							attrs["last_error_trust"] = "redacted"
						}
						g.AddNode(Node{ID: webhookNodeID, Kind: KindCommandWebhook, Label: webhook.Provider, Attrs: attrs})
						g.AddEdge(Edge{From: webhookNodeID, To: nodeID, Kind: EdgeFires})
					}
					if !webhookMore || len(webhooks) == 0 {
						break
					}
					webhookOffset += len(webhooks)
				}

				// Command chains are terminal-event bindings, not workflow
				// triggers. Show both sides of the flow while keeping source
				// workflow identity and the bounded status selector as metadata.
				for chainOffset := 0; ; {
					chains, chainMore, chainErr := b.Journal.ListCommandAutomationChainTriggersForTenantPage(ctx, journal.CommandAutomationChainTriggerFilter{
						TenantID: planTenant, AutomationID: plan.ID, Limit: pageSize, Offset: chainOffset,
					})
					if chainErr != nil {
						break
					}
					for _, chain := range chains {
						chainNodeID := commandAutomationChainNodeID(chain)
						attrs := map[string]any{
							"id": chain.ID, "tenant_id": chain.TenantID, "automation_id": chain.AutomationID,
							"automation_version": chain.AutomationVersion, "source_workflow_id": chain.SourceWorkflowID,
							"on_statuses": chain.OnStatuses, "state": chain.State, "revision": chain.Revision,
							"content_trust": "metadata",
						}
						if chain.LastFiredAt != nil && !chain.LastFiredAt.IsZero() {
							attrs["last_fired_at"] = chain.LastFiredAt.UTC().Format(time.RFC3339)
						}
						if chain.LastError != "" {
							attrs["last_error_present"] = true
							attrs["last_error_trust"] = "redacted"
						}
						g.AddNode(Node{ID: chainNodeID, Kind: KindCommandChain, Label: chain.OnStatuses, Attrs: attrs})
						g.AddEdge(Edge{From: chainNodeID, To: nodeID, Kind: EdgeFires})
						if sourceNodeID, ok := workflowNodeIDs[chain.SourceWorkflowID]; ok {
							g.AddEdge(Edge{From: chainNodeID, To: sourceNodeID, Kind: EdgeOnTerminal})
						}
					}
					if !chainMore || len(chains) == 0 {
						break
					}
					chainOffset += len(chains)
				}
			}
			if !more || len(plans) == 0 {
				break
			}
			offset += len(plans)
		}

		// Triggers FIRES workflow. Single ListTriggers scan + map back
		// to slug via wfs (avoids N + 1 round-trips).
		for offset := 0; ; {
			tgs, more, err := b.Journal.ListTriggersPage(ctx, pageSize, offset)
			if err != nil {
				// Trigger inventory is intentionally best-effort. A database that
				// predates the trigger migration should not prevent MCP startup.
				break
			}
			for _, tg := range tgs {
				workflowID, ok := workflowNodeIDs[tg.WorkflowID]
				if !ok {
					continue
				}
				tNode := Node{
					ID:    KindTrigger + ":" + tg.ID,
					Kind:  KindTrigger,
					Label: string(tg.Kind),
					Attrs: map[string]any{
						"tenant_id":   tg.TenantID,
						"workflow_id": tg.WorkflowID,
						"kind":        string(tg.Kind),
						"provider":    tg.Provider,
						"state":       tg.State,
					},
				}
				if tg.LastFiredAt != nil && !tg.LastFiredAt.IsZero() {
					tNode.Attrs["last_fired_at"] = tg.LastFiredAt.UTC().Format(time.RFC3339)
				}
				g.AddNode(tNode)
				g.AddEdge(Edge{
					From: tNode.ID,
					To:   workflowID,
					Kind: EdgeFires,
				})
			}
			if !more || len(tgs) == 0 {
				break
			}
			offset += len(tgs)
		}

		// Recent runs BELONGS_TO workflow.
		runs, err := b.Journal.ListRecentRuns(ctx, recentRunLimit)
		runTenants := make(map[string]string, len(runs))
		if err == nil {
			for _, r := range runs {
				runTenants[r.ID] = r.TenantID
				workflowID := workflowNodeIDs[r.WorkflowID]
				rid := KindRun + ":" + r.ID
				g.AddNode(Node{
					ID:    rid,
					Kind:  KindRun,
					Label: r.ID,
					Attrs: map[string]any{
						"tenant_id":    r.TenantID,
						"workflow_id":  r.WorkflowID,
						"trigger_kind": r.TriggerKind,
						"status":       r.Status,
						"started_at":   r.StartedAt.UTC().Format(time.RFC3339),
					},
				})
				if workflowID != "" {
					g.AddEdge(Edge{
						From: rid,
						To:   workflowID,
						Kind: EdgeBelongsTo,
					})
				}
			}
		}

		// DLQ items FROM run.
		dlqs, err := b.Journal.ListDeadLetterItems(ctx, 100, 0)
		if err == nil {
			for _, d := range dlqs {
				tenantID := runTenants[d.RunID]
				if tenantID == "" {
					_, tenantID, err = b.Journal.RunIdentity(ctx, d.RunID)
					if err != nil {
						// Do not classify an orphaned DLQ row as global: a
						// tenant-scoped graph must hide it until ownership can
						// be established.
						tenantID = "__unknown__"
					}
				}
				did := KindDLQItem + ":" + d.ID
				g.AddNode(Node{
					ID:    did,
					Kind:  KindDLQItem,
					Label: d.StepName,
					Attrs: map[string]any{
						"tenant_id":  tenantID,
						"run_id":     d.RunID,
						"step_name":  d.StepName,
						"error_text": d.ErrorText,
					},
				})
				g.AddEdge(Edge{
					From: did,
					To:   KindRun + ":" + d.RunID,
					Kind: EdgeFrom,
				})
			}
		}

		// Workflow USES credential, via grants.
		for offset := 0; ; {
			grants, more, err := b.Journal.ListGrantsPage(ctx, pageSize, offset)
			if err != nil {
				// Keep startup best-effort if a restored database has no grants
				// table yet. Credential authorization remains fail-closed elsewhere.
				break
			}
			for _, gr := range grants {
				workflowID, ok := workflowNodeIDs[gr.WorkflowID]
				if !ok {
					continue
				}
				workflowTenant, workflowKnown := workflowTenants[gr.WorkflowID]
				credentialTenant, credentialKnown := resolveGraphCredentialTenant(ctx, b.Journal, credentialTenants, credentialTenantLookups, gr.CredentialID)
				if !workflowKnown || !credentialKnown || workflowTenant != credentialTenant {
					// Legacy or manually repaired grant rows are untrusted. Do not
					// render an edge until both sides prove the same ownership.
					continue
				}
				g.AddEdge(Edge{
					From: workflowID,
					To:   KindCredential + ":" + gr.CredentialID,
					Kind: EdgeUses,
					Attrs: map[string]any{
						"granted_at": gr.GrantedAt.UTC().Format(time.RFC3339),
						"by":         gr.GrantedBy,
					},
				})
			}
			if !more || len(grants) == 0 {
				break
			}
			offset += len(grants)
		}
	}

	// Credentials.
	if b.Credentials != nil {
		for offset := 0; ; {
			creds, more, err := b.Credentials.ListMetadataPage(ctx, pageSize, offset)
			if err != nil {
				break
			}
			for _, c := range creds {
				attrs := map[string]any{
					"tenant_id":   c.TenantID,
					"name":        c.Name,
					"service":     c.Service,
					"provider":    c.Provider,
					"auto_rotate": c.AutoRotate,
				}
				if !c.LastRotatedAt.IsZero() {
					attrs["last_rotated_at"] = c.LastRotatedAt.UTC().Format(time.RFC3339)
				}
				if c.LastRotationError != "" {
					attrs["last_error"] = c.LastRotationError
				}
				g.AddNode(Node{
					ID:    KindCredential + ":" + c.ID,
					Kind:  KindCredential,
					Label: c.Name,
					Attrs: attrs,
				})
			}
			if !more || len(creds) == 0 {
				break
			}
			offset += len(creds)
		}
	}

	// Knowledge entries + supersedes edges.
	if b.Knowledge != nil {
		entries, err := b.Knowledge.ListMetadata(ctx, "")
		if err == nil {
			for _, fm := range entries {
				attrs := map[string]any{
					"tenant_id":      fm.Tenant,
					"topic":          fm.Topic,
					"title":          fm.Title,
					"gold":           fm.Gold,
					"citation_count": fm.CitationCount,
					"created_by":     fm.CreatedBy,
				}
				kind := KindKnowledge
				if fm.Topic == "post-mortems" {
					kind = KindPostMortem
				}
				kid := kind + ":" + fm.ID
				g.AddNode(Node{
					ID:    kid,
					Kind:  kind,
					Label: fm.Title,
					Attrs: attrs,
				})
				for _, oldID := range fm.Supersedes {
					g.AddEdge(Edge{
						From: kid,
						To:   KindKnowledge + ":" + oldID,
						Kind: EdgeSupersedes,
					})
				}
			}
		}
	}

	return g, nil
}

// resolveGraphCredentialTenant proves ownership before a graph edge is
// emitted. The metadata repository provides an efficient estate-wide cache;
// the journal fallback covers OAuth credentials and legacy rows that are not
// represented in that repository. Failed lookups are memoized as unknown so
// a malformed row cannot turn a rebuild into an unbounded query loop.
func resolveGraphCredentialTenant(ctx context.Context, j *journal.Journal, cached map[string]string, failed map[string]bool, credentialID string) (string, bool) {
	if tenant, ok := cached[credentialID]; ok {
		if tenant == "" {
			return "", false
		}
		return tenant, true
	}
	if failed[credentialID] || j == nil || strings.TrimSpace(credentialID) == "" {
		return "", false
	}
	tenant, err := j.SecretTenant(ctx, credentialID)
	tenant = strings.TrimSpace(tenant)
	if err != nil || tenant == "" {
		failed[credentialID] = true
		return "", false
	}
	if tenant == "" {
		tenant = journal.DefaultTenant
	}
	cached[credentialID] = tenant
	return tenant, true
}

func workflowNodeID(w journal.Workflow) string {
	if w.TenantID == "" || w.TenantID == journal.DefaultTenant {
		return KindWorkflow + ":" + w.Slug
	}
	return KindWorkflow + ":" + w.TenantID + ":" + w.Slug
}

func commandAutomationNodeID(a journal.CommandAutomation) string {
	if a.TenantID == "" || a.TenantID == journal.DefaultTenant {
		return KindCommandAutomation + ":" + a.Name
	}
	return KindCommandAutomation + ":" + a.TenantID + ":" + a.Name
}

func commandAutomationScheduleNodeID(s journal.CommandAutomationSchedule) string {
	if s.TenantID == "" || s.TenantID == journal.DefaultTenant {
		return KindCommandSchedule + ":" + s.ID
	}
	return KindCommandSchedule + ":" + s.TenantID + ":" + s.ID
}

func commandAutomationWebhookNodeID(w journal.CommandAutomationWebhookTrigger) string {
	if w.TenantID == "" || w.TenantID == journal.DefaultTenant {
		return KindCommandWebhook + ":" + w.ID
	}
	return KindCommandWebhook + ":" + w.TenantID + ":" + w.ID
}

func commandAutomationChainNodeID(c journal.CommandAutomationChainTrigger) string {
	if c.TenantID == "" || c.TenantID == journal.DefaultTenant {
		return KindCommandChain + ":" + c.ID
	}
	return KindCommandChain + ":" + c.TenantID + ":" + c.ID
}
