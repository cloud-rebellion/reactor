package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/commandautomations"
)

func commandDefinitionDigest(t *testing.T, raw []byte) string {
	t.Helper()
	_, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatalf("normalize command definition: %v", err)
	}
	digest := sha256.Sum256(normalized)
	return hex.EncodeToString(digest[:])
}

func boundCommandRunAdmission(t *testing.T, tenantID, automationID string, version int, raw []byte, gateDigest, actorID string) CommandRunAdmission {
	t.Helper()
	definitionSHA256 := commandDefinitionDigest(t, raw)
	return CommandRunAdmission{
		ReceiptID:  commandautomations.ReceiptIDForGateDigest(tenantID, automationID, version, definitionSHA256, gateDigest),
		GateDigest: gateDigest, DefinitionSHA256: definitionSHA256, ActorID: actorID,
	}
}

func enableCommandPlanForRun(t *testing.T, j *Journal, ctx context.Context, plan CommandAutomation) {
	t.Helper()
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, plan.TenantID, plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatalf("enable command plan: %v", err)
	}
}

func TestCommandRunAdmissionIdempotentByRunID(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_idempotent", "idempotent-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("gate"))
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	first, err := j.CreateCommandRun(ctx, "acme", "cmdrun_idempotent", plan.ID, 1, admission)
	if err != nil || !first.Created {
		t.Fatalf("first admission=%+v err=%v", first, err)
	}
	second, err := j.CreateCommandRun(ctx, "acme", "cmdrun_idempotent", plan.ID, 1, admission)
	if err != nil || second.Created || second.ID != first.ID {
		t.Fatalf("replayed admission=%+v err=%v", second, err)
	}
	changed := admission
	changed.ActorID = "bob"
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_idempotent", plan.ID, 1, changed); !errors.Is(err, ErrCommandRunConflict) {
		t.Fatalf("different admission same run id = %v", err)
	}
}

func TestCommandRunAdmissionRejectsFreeformRunID(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	for _, id := range []string{"customer secret", "ignore previous instructions", "token=abc", "å", ".hidden", strings.Repeat("x", 129)} {
		if _, err := j.CreateCommandRun(context.Background(), "acme", id, "unused", 1, CommandRunAdmission{}); err == nil || !strings.Contains(err.Error(), "invalid command run id") {
			t.Errorf("run id %q was admitted or reported a later gate: %v", id, err)
		}
	}
}

func TestCommandAutomationCreateIdempotencyBindsTenantAndPayload(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	first, replay, err := j.CreateCommandAutomationWithIdempotency(ctx, "acme", "cmd_create_idem_first", "create-idem", "same", "ops", "alice", definition, "create-key-1")
	if err != nil || replay || first.ID == "" {
		t.Fatalf("first create=%+v replay=%v err=%v", first, replay, err)
	}
	second, replay, err := j.CreateCommandAutomationWithIdempotency(ctx, "acme", "cmd_create_idem_second", "create-idem", "same", "ops", "alice", definition, "create-key-1")
	if err != nil || !replay || second.ID != first.ID {
		t.Fatalf("replayed create=%+v replay=%v err=%v", second, replay, err)
	}
	if _, _, err := j.CreateCommandAutomationWithIdempotency(ctx, "acme", "cmd_create_idem_changed", "create-idem", "changed", "ops", "alice", definition, "create-key-1"); !errors.Is(err, ErrCommandAutomationIdempotencyConflict) {
		t.Fatalf("changed metadata with reused key=%v, want ErrCommandAutomationIdempotencyConflict", err)
	}
	otherTenant, replay, err := j.CreateCommandAutomationWithIdempotency(ctx, "other", "cmd_create_idem_other", "create-idem", "same", "ops", "alice", definition, "create-key-1")
	if err != nil || replay || otherTenant.ID == first.ID {
		t.Fatalf("tenant-scoped key create=%+v replay=%v err=%v", otherTenant, replay, err)
	}
}

func TestCommandRunRetryLineageIsTenantScopedAndTerminal(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_retry_lineage", "retry-lineage", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("retry-lineage-gates"))
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	source, err := j.CreateCommandRun(ctx, "acme", "cmdrun_retry_lineage_source", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, source.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, source.ID, "worker-a", claimed.ClaimToken, CommandRunFailed, "failed"); err != nil {
		t.Fatal(err)
	}
	// A terminal row is not sufficient provenance for a retry. The source
	// automation and immutable version must match the new run, otherwise a
	// direct journal caller could create a misleading cross-plan lineage edge.
	otherDefinition := []byte(`{"steps":[{"name":"other","command":"printf other","purpose":"Other","timeout_seconds":30}]}`)
	otherPlan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_retry_lineage_other", "retry-lineage-other", "", "local", "alice", otherDefinition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, otherPlan)
	otherAdmission := boundCommandRunAdmission(t, "acme", otherPlan.ID, 1, otherDefinition, hex.EncodeToString(gate[:]), "alice")
	if _, err := j.CreateCommandRunWithRetryOf(ctx, "acme", "cmdrun_retry_lineage_cross_plan", otherPlan.ID, 1, otherAdmission, source.ID); !errors.Is(err, ErrCommandRunRetryBindingMismatch) {
		t.Fatalf("cross-plan retry source error=%v, want ErrCommandRunRetryBindingMismatch", err)
	}
	retry, err := j.CreateCommandRunWithRetryOf(ctx, "acme", "cmdrun_retry_lineage_new", plan.ID, 1, admission, source.ID)
	if err != nil || retry.RetryOf != source.ID {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	read, err := j.GetCommandRunForTenant(ctx, "acme", retry.ID)
	if err != nil || read.RetryOf != source.ID {
		t.Fatalf("read retry=%+v err=%v", read, err)
	}
	if _, err := j.CreateCommandRunWithRetryOf(ctx, "acme", "cmdrun_retry_lineage_invalid", plan.ID, 1, admission, retry.ID); !errors.Is(err, ErrCommandRunRetryNotTerminal) {
		t.Fatalf("active retry source error=%v, want ErrCommandRunRetryNotTerminal", err)
	}
	if _, err := j.CreateCommandRunWithRetryOf(ctx, "other", "cmdrun_retry_lineage_foreign", plan.ID, 1, admission, source.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign retry source error=%v, want ErrNotFound", err)
	}
	if _, err := j.CreateCommandRunWithRetryOf(ctx, "acme", source.ID, plan.ID, 1, admission, source.ID); !errors.Is(err, ErrCommandRunRetryNotTerminal) {
		t.Fatalf("same retry/source id error=%v, want ErrCommandRunRetryNotTerminal", err)
	}
}

func TestCommandRunCancellationTenantFenceAndWorkerTokenRevocation(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30},{"name":"report","command":"true","purpose":"Report","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_cancel", "cancel-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, strings.Repeat("c", 64), "alice")
	queued, err := j.CreateCommandRun(ctx, "acme", "cmdrun_cancel_queued", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := j.CancelCommandRunForTenant(ctx, "other", queued.ID, "wrong tenant"); !errors.Is(err, ErrNotFound) || outcome != CommandCancelNotPossible {
		t.Fatalf("foreign cancel outcome=%q err=%v", outcome, err)
	}
	cancelSuffix := "\npassword=supersecret"
	cancelReason := strings.Repeat("!", MaxCommandErrorBytes-len(cancelSuffix)-64) + cancelSuffix + strings.Repeat("!", 64)
	if outcome, err := j.CancelCommandRunForTenant(ctx, "acme", queued.ID, cancelReason); err != nil || outcome != CommandCancelDone {
		t.Fatalf("queued cancel outcome=%q err=%v", outcome, err)
	}
	cancelled, err := j.GetCommandRunForTenant(ctx, "acme", queued.ID)
	if err != nil || cancelled.Status != CommandRunCancelled || cancelled.ClaimToken != "" || cancelled.FinishedAt == nil {
		t.Fatalf("cancelled queued run=%+v err=%v", cancelled, err)
	}
	if strings.Contains(cancelled.ErrorText, "supersecret") || !strings.Contains(cancelled.ErrorText, "[redacted:keyed-credential]") {
		t.Fatalf("cancel reason was not redacted: %q", cancelled.ErrorText)
	}
	if len(cancelled.ErrorText) > MaxCommandErrorBytes {
		t.Fatalf("cancel reason exceeded journal bound: %d", len(cancelled.ErrorText))
	}
	if outcome, err := j.CancelCommandRunForTenant(ctx, "acme", queued.ID, "again"); err != nil || outcome != CommandCancelNotPossible {
		t.Fatalf("terminal cancel outcome=%q err=%v", outcome, err)
	}

	running, err := j.CreateCommandRun(ctx, "acme", "cmdrun_cancel_running", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, running.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	step, err := j.ClaimCommandRunStep(ctx, running.ID, "worker-a", claimed.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := j.CancelCommandRunForTenant(ctx, "acme", running.ID, "operator stop"); err != nil || outcome != CommandCancelDone {
		t.Fatalf("running cancel outcome=%q err=%v", outcome, err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", running.ID)
	if err != nil || len(steps) != 2 || steps[0].Status != CommandRunStepCancelled || steps[1].Status != CommandRunStepCancelled {
		t.Fatalf("cancelled running steps=%+v err=%v", steps, err)
	}
	if err := j.RecordCommandRunStepResult(ctx, running.ID, "worker-a", claimed.ClaimToken, 1, step.Attempt, 0, []byte("late"), nil, ""); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("stale result error=%v, want ownership loss", err)
	}
}

func TestCommandRunAdmissionRequiresEnabledCurrentVersion(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_admission_state", "admission-state-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	gate := sha256.Sum256([]byte("state-gates"))
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_disabled", plan.ID, 1, admission); !errors.Is(err, ErrCommandAutomationEnabled) {
		t.Fatalf("disabled plan admission = %v, want ErrCommandAutomationEnabled", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, true, false, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_enabled", plan.ID, 1, admission); err != nil {
		t.Fatalf("enabled current plan admission = %v", err)
	}
}

func TestCommandRunClaimRefusesPlanDisabledAfterAdmission(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_claim_disable", "claim-disable-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("claim-disable-gates"))
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_claim_disable", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, false, true, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute); !errors.Is(err, ErrCommandRunNotClaimable) {
		t.Fatalf("claim after plan disable = %v, want ErrCommandRunNotClaimable", err)
	}
	queued, err := j.GetCommandRunForTenant(ctx, "acme", run.ID)
	if err != nil || queued.Status != CommandRunQueued || queued.ClaimToken != "" {
		t.Fatalf("disabled plan claim changed durable run: %+v err=%v", queued, err)
	}
}

func TestFailQueuedCommandRunForTenantClosesStaleAdmissionWithoutClaim(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30},{"name":"report","command":"true","purpose":"Report","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_reject_queued", "reject-queued-plan", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("reject-queued-gates"))
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_reject_queued", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, "acme", plan.ID, false, true, 1); err != nil {
		t.Fatal(err)
	}
	if err := j.FailQueuedCommandRunForTenant(ctx, "acme", run.ID, "stale admission password=do-not-store"); err != nil {
		t.Fatalf("fail queued command run = %v", err)
	}
	failed, err := j.GetCommandRunForTenant(ctx, "acme", run.ID)
	if err != nil || failed.Status != CommandRunFailed || failed.ClaimToken != "" || failed.FinishedAt == nil {
		t.Fatalf("failed queued command run = %+v err=%v", failed, err)
	}
	if strings.Contains(failed.ErrorText, "do-not-store") || failed.ErrorText == "" {
		t.Fatalf("rejection reason was not safely bounded/redacted: %q", failed.ErrorText)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil || len(steps) != 2 || steps[0].Status != CommandRunStepCancelled || steps[1].Status != CommandRunStepCancelled {
		t.Fatalf("rejected queued steps = %+v err=%v", steps, err)
	}
}

func TestCommandRunJournalIsTenantScopedAndFenced(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"printf ok","purpose":"Check status","timeout_seconds":30},{"name":"report","command":"printf report","purpose":"Report status","timeout_seconds":30},{"name":"cleanup","command":"true","purpose":"Cleanup status","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_1", "fenced-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	gate := sha256.Sum256([]byte("all-gates"))
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_1", automation.ID, 1, boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(gate[:]), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != CommandRunQueued || run.DefinitionSHA256 == "" || run.Target != "ops-host" {
		t.Fatalf("created run = %+v", run)
	}
	if _, err := j.GetCommandRunForTenant(ctx, "other", "cmdrun_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read = %v, want ErrNotFound", err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", "cmdrun_1")
	if err != nil || len(steps) != 3 || steps[0].StepName != "check" || steps[0].CommandSHA256 == "" {
		t.Fatalf("steps = %+v, err=%v", steps, err)
	}
	if steps[0].StdoutText != "" || steps[0].StderrText != "" {
		t.Fatal("new command steps must not contain output")
	}

	claimed, err := j.ClaimCommandRun(ctx, "cmdrun_1", "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Status != CommandRunRunning || claimed.ClaimToken == "" || claimed.Attempt != 1 {
		t.Fatalf("claimed run = %+v", claimed)
	}
	if _, err := j.ClaimCommandRunStep(ctx, "cmdrun_1", "worker-b", claimed.ClaimToken, 1); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("wrong worker step claim = %v, want ownership loss", err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, 2); !errors.Is(err, ErrCommandRunStepOrder) {
		t.Fatalf("out-of-order step claim = %v, want order error", err)
	}
	step, err := j.ClaimCommandRunStep(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if step.Status != CommandRunStepRunning || step.Attempt != 1 {
		t.Fatalf("claimed step = %+v", step)
	}
	if err := j.RecordCommandRunStepResult(ctx, "cmdrun_1", "worker-b", claimed.ClaimToken, 1, 1, 0, []byte("ok"), nil, ""); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("wrong worker result = %v, want ownership loss", err)
	}
	if err := j.RecordCommandRunStepResult(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, 1, 1, 0, []byte("ok"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, 2); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordCommandRunStepResult(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, 2, 1, 1, nil, []byte("failed"), "exit status 1"); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishCommandRun(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, CommandRunFailed, "step failed"); err != nil {
		t.Fatal(err)
	}
	finished, err := j.GetCommandRunForTenant(ctx, "acme", "cmdrun_1")
	if err != nil {
		t.Fatal(err)
	}
	if finished.Status != CommandRunFailed || finished.ClaimToken != "" {
		t.Fatalf("finished run = %+v", finished)
	}
	steps, err = j.ListCommandRunStepsForTenant(ctx, "acme", "cmdrun_1")
	if err != nil || len(steps) != 3 || steps[2].Status != CommandRunStepCancelled || steps[2].ErrorText == "" || steps[2].FinishedAt == nil {
		t.Fatalf("failed run left pending step open: steps=%+v err=%v", steps, err)
	}
	if err := j.FinishCommandRun(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, CommandRunSucceeded, ""); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("stale terminal write = %v, want ownership loss", err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, 1); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("stale step claim = %v, want ownership loss", err)
	}
	if err := j.RecordCommandRunStepResult(ctx, "cmdrun_1", "worker-a", claimed.ClaimToken, 1, 1, 0, nil, nil, ""); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("stale step result = %v, want ownership loss", err)
	}
}

func TestCommandRunJournalBoundsAndScrubsOutput(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_2", "bounded-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	digest := sha256.Sum256([]byte("gates"))
	claimed, err := j.CreateCommandRun(ctx, "acme", "cmdrun_2", automation.ID, 1, boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(digest[:]), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = j.ClaimCommandRun(ctx, claimed.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, claimed.ID, "worker-a", claimed.ClaimToken, 1); err != nil {
		t.Fatal(err)
	}
	// Redaction markers are longer than the values they replace. Keep both
	// payloads exactly at their pre-redaction caps so the test proves the
	// post-scrub fence, rather than only the initial raw-output bound.
	stdoutSecret := "a@example.com"
	large := []byte(strings.Repeat("!", MaxCommandOutputBytes-len(stdoutSecret)) + stdoutSecret)
	secretValue := strings.Repeat("s", 32)
	secret := []byte("Authorization: Bearer " + secretValue)
	errorSecret := "\nprivate_key=" + secretValue
	longError := strings.Repeat("x", MaxCommandErrorBytes-len(errorSecret)) + errorSecret
	if err := j.RecordCommandRunStepResult(ctx, claimed.ID, "worker-a", claimed.ClaimToken, 1, 1, 0, large, secret, longError); err != nil {
		t.Fatal(err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", claimed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || !steps[0].StdoutTruncated || steps[0].StdoutBytes != len(large) || steps[0].StderrBytes != len(secret) {
		t.Fatalf("bounded step = %+v", steps)
	}
	if len(steps[0].StdoutText) > MaxCommandOutputBytes || len(steps[0].StderrText) > MaxCommandOutputBytes || len(steps[0].ErrorText) > MaxCommandErrorBytes {
		t.Fatalf("post-redaction payload exceeded journal bounds: stdout=%d stderr=%d error=%d", len(steps[0].StdoutText), len(steps[0].StderrText), len(steps[0].ErrorText))
	}
	if strings.Contains(steps[0].StdoutText, stdoutSecret) || strings.Contains(steps[0].StderrText, secretValue) || strings.Contains(steps[0].ErrorText, secretValue) {
		t.Fatalf("step output retained secret: %+v", steps[0])
	}
}

func TestCommandRunJournalRedactsPatternsCrossingOutputCap(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_boundary", "boundary-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	digest := sha256.Sum256([]byte("boundary-gates"))
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_boundary", automation.ID, 1, boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(digest[:]), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-boundary", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, claimed.ID, "worker-boundary", claimed.ClaimToken, 1); err != nil {
		t.Fatal(err)
	}
	token := "Bearer " + strings.Repeat("q", 32)
	stdout := []byte(strings.Repeat("!", MaxCommandOutputBytes-len(token)+1) + token)
	errText := strings.Repeat("x", MaxCommandErrorBytes-len(token)+1) + token
	if err := j.RecordCommandRunStepResult(ctx, claimed.ID, "worker-boundary", claimed.ClaimToken, 1, 1, 0, stdout, nil, errText); err != nil {
		t.Fatal(err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", claimed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || strings.Contains(steps[0].StdoutText, token) || strings.Contains(steps[0].ErrorText, token) {
		t.Fatalf("boundary secret survived redaction: %+v", steps)
	}
	if len(steps[0].StdoutText) > MaxCommandOutputBytes || len(steps[0].ErrorText) > MaxCommandErrorBytes {
		t.Fatalf("boundary payload exceeded caps: stdout=%d error=%d", len(steps[0].StdoutText), len(steps[0].ErrorText))
	}
}

func TestCommandRunJournalPreservesSandboxOutputTotals(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_totals", "totals-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	g := sha256.Sum256([]byte("gates"))
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_totals", automation.ID, 1, boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(g[:]), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	run, err = j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	step, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", run.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordCommandRunStepResultWithMetadata(ctx, run.ID, "worker-a", run.ClaimToken, 1, step.Attempt, 0, []byte("abcd"), []byte("xy"), "", CommandOutputMetadata{StdoutBytes: MaxCommandOutputBytes + 99, StderrBytes: 2, StdoutTruncated: true}); err != nil {
		t.Fatal(err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].StdoutBytes != MaxCommandOutputBytes+99 || !steps[0].StdoutTruncated || steps[0].StderrBytes != 2 {
		t.Fatalf("sandbox output totals = %+v", steps)
	}
}

func TestCommandRunJournalAppendsLiveOutputUnderClaim(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"stream","command":"printf stream","purpose":"Stream","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_live_output", "live-output", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("live-output-gate"))
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_live_output", plan.ID, 1, boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-live", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	step, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-live", claimed.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AppendCommandRunStepOutput(ctx, run.ID, "worker-live", claimed.ClaimToken, 1, step.Attempt, "stdout", []byte("partial ")); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendCommandRunStepOutput(ctx, run.ID, "worker-live", claimed.ClaimToken, 1, step.Attempt, "stdout", []byte("output")); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendCommandRunStepOutput(ctx, run.ID, "worker-live", claimed.ClaimToken, 1, step.Attempt, "stderr", []byte("warning")); err != nil {
		t.Fatal(err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil || len(steps) != 1 {
		t.Fatalf("live step projection=%+v err=%v", steps, err)
	}
	if steps[0].StdoutText != "partial output" || steps[0].StdoutBytes != len("partial output") || steps[0].StderrText != "warning" || steps[0].StderrBytes != len("warning") {
		t.Fatalf("live output projection=%+v", steps[0])
	}
	var attemptStdout, attemptStderr string
	var attemptStdoutBytes, attemptStderrBytes int
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT stdout_text, stderr_text, stdout_bytes, stderr_bytes FROM command_run_step_attempts WHERE run_id = $1 AND step_seq = $2 AND attempt = $3`), run.ID, 1, step.Attempt).Scan(&attemptStdout, &attemptStderr, &attemptStdoutBytes, &attemptStderrBytes); err != nil {
		t.Fatal(err)
	}
	if attemptStdout != "partial output" || attemptStderr != "warning" || attemptStdoutBytes != len("partial output") || attemptStderrBytes != len("warning") {
		t.Fatalf("live attempt projection stdout=%q stderr=%q bytes=%d/%d", attemptStdout, attemptStderr, attemptStdoutBytes, attemptStderrBytes)
	}
	if err := j.AppendCommandRunStepOutput(ctx, run.ID, "other-worker", claimed.ClaimToken, 1, step.Attempt, "stdout", []byte("stale")); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("foreign live append=%v, want ownership loss", err)
	}
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-live", claimed.ClaimToken, 1, step.Attempt, 0, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	finalSteps, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil || len(finalSteps) != 1 || finalSteps[0].StdoutText != "partial output" || finalSteps[0].StderrText != "warning" {
		t.Fatalf("terminal result erased streamed output: %+v err=%v", finalSteps, err)
	}
}

func TestCommandRunAdmissionRejectsStaleDefinitionReceipt(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_digest", "digest-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	gate := sha256.Sum256([]byte("gates"))
	_, err = j.CreateCommandRun(ctx, "acme", "cmdrun_digest", automation.ID, 1, CommandRunAdmission{
		ReceiptID: "receipt_digest", GateDigest: hex.EncodeToString(gate[:]), DefinitionSHA256: strings.Repeat("0", 64), ActorID: "alice",
	})
	if !errors.Is(err, ErrCommandRunDefinitionMismatch) {
		t.Fatalf("stale definition receipt error = %v, want ErrCommandRunDefinitionMismatch", err)
	}
	if _, err = j.GetCommandRunForTenant(ctx, "acme", "cmdrun_digest"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched admission created run: %v", err)
	}
}

func TestCommandRunAdmissionRejectsMismatchedReceiptBinding(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_binding", "binding-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	gate := sha256.Sum256([]byte("gates"))
	gateDigest := hex.EncodeToString(gate[:])
	valid := boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, gateDigest, "alice")
	otherGate := sha256.Sum256([]byte("other gates"))
	for _, tc := range []struct {
		name      string
		admission CommandRunAdmission
	}{
		{name: "unrelated receipt ID", admission: func() CommandRunAdmission { a := valid; a.ReceiptID = "receipt_other"; return a }()},
		{name: "changed gate digest", admission: func() CommandRunAdmission { a := valid; a.GateDigest = hex.EncodeToString(otherGate[:]); return a }()},
		{name: "different tenant binding", admission: func() CommandRunAdmission {
			a := valid
			a.ReceiptID = commandautomations.ReceiptIDForGateDigest("other", automation.ID, 1, a.DefinitionSHA256, a.GateDigest)
			return a
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := j.CreateCommandRun(ctx, "acme", "cmdrun_binding", automation.ID, 1, tc.admission)
			if !errors.Is(err, ErrCommandRunBindingMismatch) {
				t.Fatalf("mismatched binding error = %v, want ErrCommandRunBindingMismatch", err)
			}
			if _, err := j.GetCommandRunForTenant(ctx, "acme", "cmdrun_binding"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("mismatched binding created run: %v", err)
			}
		})
	}
	if _, err := j.CreateCommandRun(ctx, "acme", "cmdrun_binding", automation.ID, 1, valid); err != nil {
		t.Fatalf("matching binding rejected: %v", err)
	}
}

func TestCommandRunInspectionPagesAreTenantScopedAndBounded(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_page", "page-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	gate := sha256.Sum256([]byte("page-gates"))
	admission := boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_page", automation.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	if runs, err := j.ListCommandRunsForTenantPage(ctx, CommandRunFilter{TenantID: "other", Limit: 2}); err != nil || len(runs) != 0 {
		t.Fatalf("foreign command run page = %+v, err=%v", runs, err)
	}
	runs, err := j.ListCommandRunsForTenantPage(ctx, CommandRunFilter{TenantID: "acme", Limit: 2})
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID || runs[0].ClaimToken != "" {
		t.Fatalf("command run page = %+v, err=%v", runs, err)
	}
	// Imported rows can predate the write-time error cap. Every command-run
	// read projection must omit that payload before it reaches an MCP or worker
	// process while preserving a safe byte-count receipt.
	legacyRunError := strings.Repeat("!", MaxCommandErrorBytes+37)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_runs SET error_text = $1 WHERE id = $2`), legacyRunError, run.ID); err != nil {
		t.Fatalf("seed legacy command run error: %v", err)
	}
	boundedRun, err := j.GetCommandRunForTenant(ctx, "acme", run.ID)
	if err != nil || boundedRun.ErrorText != "" || boundedRun.ErrorBytes != len([]byte(legacyRunError)) || !boundedRun.ErrorTruncated {
		t.Fatalf("bounded command run = %+v, err=%v", boundedRun, err)
	}
	pageRun, err := j.ListCommandRunsForTenantPage(ctx, CommandRunFilter{TenantID: "acme", Limit: 2})
	if err != nil || len(pageRun) != 1 || pageRun[0].ErrorText != "" || pageRun[0].ErrorBytes != len([]byte(legacyRunError)) || !pageRun[0].ErrorTruncated {
		t.Fatalf("bounded command run page = %+v, err=%v", pageRun, err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1); err != nil {
		t.Fatal(err)
	}
	large := []byte(strings.Repeat("x", (64<<10)+32))
	largeError := strings.Repeat("!", MaxCommandErrorBytes)
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 1, 1, 0, large, nil, largeError); err != nil {
		t.Fatal(err)
	}
	steps, err := j.ListCommandRunStepsPageForTenantBounded(ctx, "acme", run.ID, 2, 0, 64<<10, 128)
	if err != nil || len(steps) != 1 || !steps[0].StdoutTruncated || steps[0].StdoutBytes != len(large) || steps[0].StdoutText != "" || !steps[0].ErrorTruncated || steps[0].ErrorBytes != len(largeError) || steps[0].ErrorText != "" {
		t.Fatalf("bounded command steps = %+v, err=%v", steps, err)
	}
	if _, err := j.ListCommandRunStepsPageForTenantBounded(ctx, "other", run.ID, 2, 0, 64<<10, 128); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign command steps error = %v, want ErrNotFound", err)
	}
	if _, err := j.ListCommandRunStepsPageForTenantBounded(ctx, "other", run.ID, 2, 1, 64<<10, 128); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign command steps offset error = %v, want ErrNotFound", err)
	}
	// A legacy/imported row may have a stale zero byte counter. The bounded
	// projection must still omit the oversized stored value and report that it
	// was truncated based on the actual UTF-8 byte length.
	legacyOutput := strings.Repeat("y", (64<<10)+1)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_run_steps SET stdout_text = $1, stdout_bytes = 0, stdout_truncated = $2 WHERE run_id = $3 AND step_seq = $4`), legacyOutput, j.boolValue(false), run.ID, 1); err != nil {
		t.Fatalf("seed stale command output counters: %v", err)
	}
	legacySteps, err := j.ListCommandRunStepsPageForTenantBounded(ctx, "acme", run.ID, 2, 0, 64<<10, 128)
	if err != nil || len(legacySteps) != 1 || !legacySteps[0].StdoutTruncated || legacySteps[0].StdoutText != "" {
		t.Fatalf("stale-counter bounded command steps = %+v, err=%v", legacySteps, err)
	}
}

func TestQueuedCommandRecoveryPageIsOldestFirst(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_recovery_order", "recovery-order", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	gate := sha256.Sum256([]byte("recovery-order-gates"))
	admission := boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	oldRun, err := j.CreateCommandRun(ctx, "acme", "cmdrun_recovery_old", automation.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	newRun, err := j.CreateCommandRun(ctx, "acme", "cmdrun_recovery_new", automation.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_runs SET created_at = $1 WHERE id = $2`), j.formatTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), oldRun.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_runs SET created_at = $1 WHERE id = $2`), j.formatTime(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)), newRun.ID); err != nil {
		t.Fatal(err)
	}
	runs, err := j.ListQueuedCommandRunsForTenantPage(ctx, "acme", 2)
	if err != nil || len(runs) != 2 {
		t.Fatalf("queued recovery page = %+v err=%v", runs, err)
	}
	if runs[0].ID != oldRun.ID || runs[1].ID != newRun.ID {
		t.Fatalf("queued recovery order = [%s %s], want oldest first", runs[0].ID, runs[1].ID)
	}
}

func TestCommandRunOutputBoundsPreserveUTF8(t *testing.T) {
	text, bytes, truncated := boundCommandOutput([]byte("éé"), 3)
	if !truncated || bytes != len([]byte("éé")) || !utf8.ValidString(text) || len(text) > 3 {
		t.Fatalf("bounded output = %q bytes=%d truncated=%v", text, bytes, truncated)
	}
	errText, errBytes, errTruncated := boundCommandError(strings.Repeat("é", MaxCommandErrorBytes))
	if !errTruncated || errBytes != MaxCommandErrorBytes*2 || !utf8.ValidString(errText) || len(errText) > MaxCommandErrorBytes {
		t.Fatalf("bounded error bytes=%d text_bytes=%d truncated=%v", errBytes, len(errText), errTruncated)
	}
}

func TestCommandRunLeaseHeartbeatAndReaperFenceStaleWorkers(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_lease", "lease-plan", "", "", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	gate := sha256.Sum256([]byte("lease-gates"))
	admission := boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_lease", automation.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.VerifyCommandRunLease(ctx, run.ID, "worker-a", claimed.ClaimToken); err != nil {
		t.Fatalf("live command lease rejected: %v", err)
	}
	if err := j.ExtendCommandRunLease(ctx, run.ID, "worker-a", claimed.ClaimToken, time.Minute); err != nil {
		t.Fatalf("live command lease renewal failed: %v", err)
	}
	if err := j.ExtendCommandRunLease(ctx, run.ID, "worker-b", claimed.ClaimToken, time.Minute); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("wrong worker renewed command lease: %v", err)
	}
	// Model a worker that stopped heartbeating. The reaper must clear the
	// exact old generation, and the old worker must fail every later fence.
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_runs SET lease_expires_at = $1 WHERE id = $2`), j.formatTime(time.Now().UTC().Add(-time.Minute)), run.ID); err != nil {
		t.Fatalf("expire command lease: %v", err)
	}
	if err := j.VerifyCommandRunLease(ctx, run.ID, "worker-a", claimed.ClaimToken); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("expired command lease verified: %v", err)
	}
	if err := j.ExtendCommandRunLease(ctx, run.ID, "worker-a", claimed.ClaimToken, time.Minute); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("expired command lease renewed: %v", err)
	}
	// Every durable mutation must enforce the live lease itself. The reaper
	// may run slightly later, but an expired worker must not claim, finish, or
	// record a result in that window.
	if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("expired command lease claimed a step before reap: %v", err)
	}
	if err := j.FinishCommandRun(ctx, run.ID, "worker-a", claimed.ClaimToken, CommandRunFailed, "expired"); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("expired command lease finished run before reap: %v", err)
	}
	reaped, err := j.ReapExpiredCommandRunLeases(ctx)
	if err != nil || reaped != 1 {
		t.Fatalf("reap expired command lease = %d, %v; want 1", reaped, err)
	}
	requeued, err := j.GetCommandRunForTenant(ctx, "acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if requeued.Status != CommandRunQueued || requeued.ClaimOwner != "" || requeued.ClaimToken != "" || requeued.LeaseExpiresAt != nil {
		t.Fatalf("requeued command run retained old lease: %+v", requeued)
	}
	if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1); !errors.Is(err, ErrCommandRunOwnershipLost) {
		t.Fatalf("stale worker claimed step after command lease reap: %v", err)
	}
	replacement, err := j.ClaimCommandRun(ctx, run.ID, "worker-b", time.Minute)
	if err != nil {
		t.Fatalf("replacement command claim failed: %v", err)
	}
	if replacement.ClaimToken == claimed.ClaimToken || replacement.Attempt != 2 {
		t.Fatalf("replacement command claim = %+v", replacement)
	}
}

func TestCommandRunLeaseReaperClosesInFlightStepForRetry(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"prepare","command":"true","purpose":"Prepare","timeout_seconds":30},{"name":"deploy","command":"true","purpose":"Deploy","timeout_seconds":30}]}`)
	automation, err := j.CreateCommandAutomation(ctx, "acme", "cmd_run_recovery", "recovery-plan", "", "ops-host", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, automation)
	g := sha256.Sum256([]byte("recovery-gates"))
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_recovery", automation.ID, 1, boundCommandRunAdmission(t, "acme", automation.ID, 1, definition, hex.EncodeToString(g[:]), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 1, first.Attempt, 0, []byte("prepared"), nil, ""); err != nil {
		t.Fatal(err)
	}
	second, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a worker that persisted a failed step result but crashed before
	// its parent terminal transition. Reaping must retain step 1's success,
	// preserve the failed attempt audit row, and make step 2 retryable rather
	// than leaving its failed projection permanently unclaimable.
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 2, second.Attempt, 1, nil, []byte("deploy failed"), "deploy failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE command_runs SET lease_expires_at = $1 WHERE id = $2`), j.formatTime(time.Now().UTC().Add(-time.Minute)), run.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := j.ReapExpiredCommandRunLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap expired command run = %d, %v; want 1", n, err)
	}
	steps, err := j.ListCommandRunStepsForTenant(ctx, "acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 || steps[0].Status != CommandRunStepSucceeded || steps[1].Status != CommandRunStepPending {
		t.Fatalf("recovered step projections = %+v", steps)
	}
	var attemptStatus, attemptError string
	var finishedAt any
	if err := j.db.QueryRowContext(ctx, j.bind(`SELECT status, error_text, finished_at FROM command_run_step_attempts WHERE run_id = $1 AND step_seq = $2 AND attempt = $3`), run.ID, 2, second.Attempt).Scan(&attemptStatus, &attemptError, &finishedAt); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != CommandRunStepFailed || attemptError != "deploy failed" || finishedAt == nil {
		t.Fatalf("expired step attempt = status=%q error=%q finished=%v", attemptStatus, attemptError, finishedAt)
	}
	replacement, err := j.ClaimCommandRun(ctx, run.ID, "worker-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Attempt != 2 || replacement.ClaimToken == claimed.ClaimToken {
		t.Fatalf("replacement claim = %+v", replacement)
	}
	if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-b", replacement.ClaimToken, 1); !errors.Is(err, ErrCommandRunNotClaimable) {
		t.Fatalf("replacement attempted succeeded step = %v, want ErrCommandRunNotClaimable", err)
	}
	retried, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-b", replacement.ClaimToken, 2)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Attempt != second.Attempt+1 || retried.Status != CommandRunStepRunning {
		t.Fatalf("retried step = %+v", retried)
	}
}
