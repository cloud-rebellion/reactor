package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestResolveAdmittedMailSendIsTenantFencedImmutableAndNotAReplay(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	testMailSendResolutionLifecycle(t, j)
}

func TestResolveAdmittedMailSendPostgres(t *testing.T) {
	j, cleanup := newOwnedStepPostgresJournal(t)
	defer cleanup()
	testMailSendResolutionLifecycle(t, j)
}

func testMailSendResolutionLifecycle(t *testing.T, j *Journal) {
	t.Helper()
	ctx := context.Background()
	const secret = "private-recipient-token-payload"
	for _, tenant := range []string{"acme", "other"} {
		if err := j.CreateWorkflowInTenant(ctx, "wf_resolve_"+tenant, "resolve-"+tenant, "hash", "0.1.0", json.RawMessage(`{}`), tenant); err != nil {
			t.Fatal(err)
		}
		if err := j.CreateRun(ctx, "run_resolve_"+tenant, "wf_resolve_"+tenant, "manual", json.RawMessage(`{"recipient":"`+secret+`"}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ClaimStepAttemptSeq(ctx, "run_resolve_"+tenant, "send", 1, 3, secret, "input"); err != nil {
			t.Fatal(err)
		}
	}
	admitted, err := j.AdmitMailSend(ctx, "run_resolve_acme", "", "send", 1, 1, secret, mailTestDigest,
		MailSendTarget{ProviderID: "google", ConnectionID: "conn_resolution"})
	if err != nil {
		t.Fatal(err)
	}
	input := MailSendResolutionInput{
		TenantID: "acme", RunID: "run_resolve_acme", IntentID: admitted.IntentID, Seq: 1,
		TargetProviderID: "google", TargetConnectionID: "conn_resolution",
		Decision: "provider_accepted", EvidenceKind: "provider_audit", EvidenceSHA256: mailTestDigest,
		ActorID: "operator_1",
	}
	foreign := input
	foreign.TenantID = "other"
	if _, err := j.ResolveAdmittedMailSend(ctx, foreign); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign resolution = %v", err)
	}
	for _, change := range []func(*MailSendResolutionInput){
		func(i *MailSendResolutionInput) { i.RunID = "run_resolve_other" },
		func(i *MailSendResolutionInput) { i.Seq = 2 },
		func(i *MailSendResolutionInput) { i.TargetConnectionID = "wrong" },
		func(i *MailSendResolutionInput) { i.TargetProviderID = "microsoft" },
	} {
		wrong := input
		change(&wrong)
		if _, err := j.ResolveAdmittedMailSend(ctx, wrong); !errors.Is(err, ErrMailSendIdentityMismatch) {
			t.Fatalf("wrong exact identity = %v", err)
		}
	}
	wrongEvidence := input
	wrongEvidence.EvidenceKind = "manual_decision"
	if _, err := j.ResolveAdmittedMailSend(ctx, wrongEvidence); err == nil {
		t.Fatal("provider claim accepted a manual-decision evidence kind")
	}
	wrongEvidence = input
	wrongEvidence.EvidenceSHA256 = strings.Repeat("x", 64)
	if _, err := j.ResolveAdmittedMailSend(ctx, wrongEvidence); err == nil {
		t.Fatal("invalid evidence digest accepted")
	}
	queue, _, _, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 10, "")
	if err != nil || len(queue) != 1 || queue[0].ID != admitted.IntentID {
		t.Fatalf("unresolved queue = %+v, %v", queue, err)
	}
	if _, err := j.ResolveAdmittedMailSend(ctx, input); !errors.Is(err, ErrMailSendRunActive) {
		t.Fatalf("active provider write was resolved = %v", err)
	}
	if err := j.MarkRunFinished(ctx, input.RunID, "failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO mail_send_resolutions
		(id, intent_id, tenant_id, run_id, decision, evidence_kind, evidence_sha256, actor_id, resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`),
		"mailresolve_forged", admitted.IntentID, "other", "run_resolve_other", "closed_unverified",
		"manual_decision", mailTestDigest, "operator_1", j.now()); err == nil {
		t.Fatal("database allowed a cross-tenant resolution to hide an intent")
	}
	receipt, err := j.ResolveAdmittedMailSend(ctx, input)
	if err != nil || receipt.ID == "" || receipt.Replayed || receipt.Decision != input.Decision || receipt.ResolvedAt.IsZero() {
		t.Fatalf("resolution = %+v, %v", receipt, err)
	}
	replayed, err := j.ResolveAdmittedMailSend(ctx, input)
	if err != nil || !replayed.Replayed || replayed.ID != receipt.ID {
		t.Fatalf("lost-response replay = %+v, %v", replayed, err)
	}
	conflicting := input
	conflicting.Decision = "provider_rejected"
	if _, err := j.ResolveAdmittedMailSend(ctx, conflicting); !errors.Is(err, ErrMailSendResolutionConflict) {
		t.Fatalf("conflicting resolution = %v", err)
	}
	if err := j.ConfirmMailSend(ctx, admitted.IntentID, "google", "private-provider-message-id"); !errors.Is(err, ErrMailSendResolutionConflict) {
		t.Fatalf("late provider confirmation after resolution = %v", err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE mail_send_intents SET status = 'confirmed',
		provider_id = 'google', confirmed_at = $1 WHERE id = $2`), j.now(), admitted.IntentID); err == nil {
		t.Fatal("database allowed provider confirmation after operator resolution")
	}
	queue, _, _, err = j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 10, "")
	if err != nil || len(queue) != 0 {
		t.Fatalf("resolved queue = %+v, %v", queue, err)
	}
	rows, _, err := j.ListMailSendIntentsForRunTenant(ctx, input.RunID, input.TenantID, 10, 0)
	if err != nil || len(rows) != 1 || rows[0].Status != "admitted" || rows[0].Resolution == nil ||
		rows[0].Resolution.ID != receipt.ID || rows[0].Resolution.Decision != "provider_accepted" {
		t.Fatalf("retained original intent and finding = %+v, %v", rows, err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE mail_send_resolutions SET decision = 'closed_unverified' WHERE id = $1`), receipt.ID); err == nil {
		t.Fatal("resolution ledger allowed in-place modification")
	}
	setRunTimes(t, j, ctx, input.RunID, time.Now().UTC().Add(-30*24*time.Hour))
	if n, err := j.PurgeTerminalRunsOlderThan(ctx, time.Now().UTC().Add(-7*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("resolved run retention = %d, %v", n, err)
	}
	var remaining int
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT COUNT(*) FROM mail_send_resolutions WHERE id = $1`), receipt.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("orphaned resolution after retention = %d, %v", remaining, err)
	}
}

func TestResolveAdmittedMailSendClosedUnverifiedDoesNotClaimProviderAcceptance(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "key", "input"); err != nil {
		t.Fatal(err)
	}
	admitted, err := j.AdmitMailSend(ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest,
		MailSendTarget{ProviderID: "google", ConnectionID: "conn_manual"})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed"); err != nil {
		t.Fatal(err)
	}
	receipt, err := j.ResolveAdmittedMailSend(ctx, MailSendResolutionInput{
		TenantID: DefaultTenant, RunID: "run_1", IntentID: admitted.IntentID, Seq: 1,
		TargetProviderID: "google", TargetConnectionID: "conn_manual", Decision: "closed_unverified",
		EvidenceKind: "manual_decision", EvidenceSHA256: mailTestDigest, ActorID: "operator_1",
	})
	if err != nil || receipt.Decision != "closed_unverified" {
		t.Fatalf("manual closure = %+v, %v", receipt, err)
	}
	rows, _, err := j.ListMailSendIntentsForRunTenant(ctx, "run_1", DefaultTenant, 10, 0)
	if err != nil || len(rows) != 1 || rows[0].Status != "admitted" || rows[0].Resolution == nil ||
		rows[0].Resolution.Decision != "closed_unverified" || rows[0].MessageIDKnown {
		t.Fatalf("manual closure misstated acceptance = %+v, %v", rows, err)
	}
}

func TestResolveAdmittedMailSendRefusesPriorProviderConfirmation(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "key", "input"); err != nil {
		t.Fatal(err)
	}
	admitted, err := j.AdmitMailSend(ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest,
		MailSendTarget{ProviderID: "google", ConnectionID: "conn_prior"})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.ConfirmMailSend(ctx, admitted.IntentID, "google", "private-provider-id"); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "failed"); err != nil {
		t.Fatal(err)
	}
	_, err = j.ResolveAdmittedMailSend(ctx, MailSendResolutionInput{
		TenantID: DefaultTenant, RunID: "run_1", IntentID: admitted.IntentID, Seq: 1,
		TargetProviderID: "google", TargetConnectionID: "conn_prior", Decision: "provider_accepted",
		EvidenceKind: "provider_record", EvidenceSHA256: mailTestDigest, ActorID: "operator_1",
	})
	if !errors.Is(err, ErrMailSendNotAdmitted) {
		t.Fatalf("manual finding after durable provider confirmation = %v", err)
	}
}
