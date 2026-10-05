package commandrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

type fakeJournal struct {
	definition journal.CommandAutomationVersion
	automation journal.CommandAutomation
	run        journal.CommandRun
	step       journal.CommandRunStep
	finished   string
	recorded   bool
	stdout     []byte
	stderr     []byte
	errText    string
}

type scheduledFakeJournal struct {
	*fakeJournal
	schedule journal.CommandAutomationSchedule
}

func (f *scheduledFakeJournal) GetCommandAutomationScheduleForTenant(_ context.Context, tenantID, id string) (journal.CommandAutomationSchedule, error) {
	if tenantID != f.schedule.TenantID || id != f.schedule.ID {
		return journal.CommandAutomationSchedule{}, journal.ErrNotFound
	}
	return f.schedule, nil
}

func TestRunnerAdmitsDurableCommandScheduleWithBoundedProvenance(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":1,"expected_exit_code":0}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	receipt := commandautomations.EvaluateExecutionGates(d, caps)
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_schedule", 1, digestHex, receipt)
	schedule := journal.CommandAutomationSchedule{ID: "sched_1", TenantID: "acme", AutomationID: "cmd_schedule", AutomationVersion: 1, DefinitionSHA256: digestHex, ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, ActorID: "scheduler-admin", State: journal.CommandAutomationScheduleActive}
	fj := &scheduledFakeJournal{fakeJournal: &fakeJournal{definition: journal.CommandAutomationVersion{AutomationID: "cmd_schedule", Version: 1, DefinitionJSON: normalized}, automation: journal.CommandAutomation{ID: "cmd_schedule", TenantID: "acme", Target: "local", Enabled: true, CurrentVersion: 1}}, schedule: schedule}
	r := &Runner{Journal: fj, Sandbox: &fakeSandbox{}, Enabled: true, TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }), ScheduledCapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
		return commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true}, nil
	}}
	result, err := r.AdmitScheduled(context.Background(), Request{TenantID: "acme", AutomationID: "cmd_schedule", Version: 1, TriggerID: schedule.ID, TriggerEventID: "event_1"}, schedule)
	if err != nil {
		t.Fatalf("scheduled admission failed: %v", err)
	}
	if result.Run.ID == "" || result.Run.Admission.TriggerID != schedule.ID || result.Run.Admission.TriggerEventID != "event_1" || result.Run.Admission.ActorID != schedule.ActorID {
		t.Fatalf("scheduled run provenance = %+v", result.Run)
	}
	if result.Receipt.Status != "ready" {
		t.Fatalf("scheduled receipt = %+v", result.Receipt)
	}
}

func (f *fakeJournal) GetCommandAutomation(context.Context, string, string) (journal.CommandAutomation, error) {
	return f.automation, nil
}

func (f *fakeJournal) GetCommandAutomationVersion(context.Context, string, string, int) (journal.CommandAutomationVersion, error) {
	return f.definition, nil
}

func (f *fakeJournal) CreateCommandRun(_ context.Context, tenantID, runID, automationID string, version int, admission journal.CommandRunAdmission) (journal.CommandRun, error) {
	f.run = journal.CommandRun{ID: runID, TenantID: tenantID, AutomationID: automationID, AutomationVersion: version, Target: f.automation.Target, Admission: admission, Status: journal.CommandRunQueued, Created: true}
	return f.run, nil
}

func (f *fakeJournal) ClaimCommandRun(context.Context, string, string, time.Duration) (journal.CommandRun, error) {
	f.run.Status, f.run.ClaimOwner, f.run.ClaimToken, f.run.Attempt = journal.CommandRunRunning, "worker", "claim", 1
	return f.run, nil
}

func (f *fakeJournal) VerifyCommandRunLease(context.Context, string, string, string) error {
	return nil
}
func (f *fakeJournal) ExtendCommandRunLease(context.Context, string, string, string, time.Duration) error {
	return nil
}

func (f *fakeJournal) ClaimCommandRunStep(context.Context, string, string, string, int) (journal.CommandRunStep, error) {
	f.step = journal.CommandRunStep{RunID: f.run.ID, StepSeq: 1, StepName: "check", Attempt: 1, Status: journal.CommandRunStepRunning}
	return f.step, nil
}

func (f *fakeJournal) RecordCommandRunStepResult(_ context.Context, _ string, _ string, _ string, _, _, exitCode int, stdout, stderr []byte, errText string) error {
	f.recorded = true
	f.stdout = append([]byte(nil), stdout...)
	f.stderr = append([]byte(nil), stderr...)
	f.errText = errText
	if exitCode != 0 {
		return errors.New("unexpected exit code")
	}
	return nil
}

func (f *fakeJournal) FinishCommandRun(_ context.Context, _ string, _ string, _ string, status, _ string) error {
	f.finished = status
	f.run.Status = status
	return nil
}

func (f *fakeJournal) GetCommandRunForTenant(context.Context, string, string) (journal.CommandRun, error) {
	return f.run, nil
}

func TestRunnerRejectsQueuedPermanentAdmissionFailure(t *testing.T) {
	admission := journal.CommandRunAdmission{
		ReceiptID:        "receipt",
		GateDigest:       strings.Repeat("a", 64),
		DefinitionSHA256: strings.Repeat("b", 64),
		ActorID:          "alice",
	}
	fj := &fakeJournal{run: journal.CommandRun{
		ID:                "run-reject",
		TenantID:          "acme",
		AutomationID:      "cmd_1",
		AutomationVersion: 1,
		Admission:         admission,
		Status:            journal.CommandRunQueued,
	}}
	r := &Runner{Journal: fj}
	err := r.RejectQueued(context.Background(), Request{
		// The queue item is stale by construction; rejection must still close
		// the durable run instead of leaving it queued forever because the old
		// plan/version projection no longer matches.
		TenantID: "acme", AutomationID: "deleted-plan", Version: 99, RunID: "run-reject", WorkerID: "worker", Admission: journal.CommandRunAdmission{
			ReceiptID: "stale", GateDigest: strings.Repeat("c", 64), DefinitionSHA256: strings.Repeat("d", 64), ActorID: "old-actor",
		},
	}, ErrBlocked)
	if err != nil {
		t.Fatalf("reject queued returned error: %v", err)
	}
	if fj.finished != journal.CommandRunFailed || fj.run.Status != journal.CommandRunFailed {
		t.Fatalf("finished=%q run_status=%q, want failed", fj.finished, fj.run.Status)
	}
}

func TestRunnerRejectsQueuedCredentialRunWhenMaterializerIsUnavailable(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"use-secret","command":"true","purpose":"Use grant","timeout_seconds":1,"expected_exit_code":0,"credential_ids":["cred_api"]}]}`)
	_, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	admission := journal.CommandRunAdmission{ReceiptID: "receipt", GateDigest: "gate", DefinitionSHA256: digestHex, ActorID: "alice"}
	fj := &fakeJournal{
		definition: journal.CommandAutomationVersion{AutomationID: "cmd_queued_credential", Version: 1, DefinitionJSON: normalized},
		automation: journal.CommandAutomation{ID: "cmd_queued_credential", TenantID: "acme", Target: "local", Enabled: true},
		run: journal.CommandRun{
			ID: "run-queued-credential", TenantID: "acme", AutomationID: "cmd_queued_credential", AutomationVersion: 1,
			DefinitionSHA256: digestHex, Admission: admission, Status: journal.CommandRunQueued,
		},
	}
	fs := &fakeSandbox{}
	r := &Runner{
		Journal: fj, Sandbox: fs, Enabled: true,
		TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }),
	}
	_, err = r.ExecuteQueued(context.Background(), Request{
		TenantID: "acme", AutomationID: "cmd_queued_credential", Version: 1, RunID: fj.run.ID,
		WorkerID: "worker", LeaseTTL: 5 * time.Second, Admission: admission,
	})
	if !errors.Is(err, ErrCredentialBoundary) {
		t.Fatalf("queued credential run error = %v, want ErrCredentialBoundary", err)
	}
	if fj.run.Status != journal.CommandRunQueued || fs.calls != 0 {
		t.Fatalf("unsafe queued credential run changed state: status=%q sandbox_calls=%d", fj.run.Status, fs.calls)
	}
}

func TestRunnerCancellationOwnershipLossIsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fj := &fakeJournal{}
	r := &Runner{Journal: fj}
	err := r.finishAfterError(ctx, "run-cancel", "worker", "stale-token", journal.ErrCommandRunOwnershipLost)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ownership loss = %v, want context.Canceled", err)
	}
	if fj.finished != "" {
		t.Fatalf("stale cancellation attempted a second terminal write: %q", fj.finished)
	}
}

type fakeSandbox struct{ calls int }

func (f *fakeSandbox) Profile() SandboxProfile {
	return SandboxProfile{Name: "test", NonRoot: true, NoHostMounts: true, NetworkDisabled: true, ReadOnlyRoot: true, ResourceLimited: true, MaxOutputBytes: 1024}
}

func (f *fakeSandbox) Execute(context.Context, SandboxRequest) (SandboxResult, error) {
	f.calls++
	return SandboxResult{ExitCode: 0, Stdout: []byte("ok")}, nil
}

func (f *fakeSandbox) ExecuteWithCredentials(_ context.Context, _ SandboxRequest, materialized CredentialMaterialization) (SandboxResult, error) {
	f.calls++
	if len(materialized.Bindings) != 1 || string(materialized.Bindings[0].Value) != "runner-secret" {
		return SandboxResult{ExitCode: -1, ErrorText: "credential binding mismatch"}, errors.New("credential binding mismatch")
	}
	return SandboxResult{ExitCode: 0, Stdout: []byte("prefix runner-secret suffix"), Stderr: []byte("runner-secret")}, nil
}

type blockingSandbox struct{ started chan struct{} }

func (s *blockingSandbox) Profile() SandboxProfile {
	return SandboxProfile{Name: "test", NonRoot: true, NoHostMounts: true, NetworkDisabled: true, ReadOnlyRoot: true, ResourceLimited: true, MaxOutputBytes: 1024}
}

func (s *blockingSandbox) Execute(ctx context.Context, _ SandboxRequest) (SandboxResult, error) {
	close(s.started)
	<-ctx.Done()
	// Keep the result shape valid so the runner can persist the bounded step
	// receipt before it returns the parent-context cancellation.
	return SandboxResult{ExitCode: 0}, ctx.Err()
}

type clearingErrorSandbox struct{}

func (clearingErrorSandbox) Profile() SandboxProfile {
	return SandboxProfile{Name: "test", NonRoot: true, NoHostMounts: true, NetworkDisabled: true, ReadOnlyRoot: true, ResourceLimited: true, MaxOutputBytes: 1024}
}

func (clearingErrorSandbox) Execute(context.Context, SandboxRequest) (SandboxResult, error) {
	return SandboxResult{ExitCode: 0}, nil
}

func (clearingErrorSandbox) ExecuteWithCredentials(_ context.Context, _ SandboxRequest, materialized CredentialMaterialization) (SandboxResult, error) {
	secret := append([]byte(nil), materialized.Bindings[0].Value...)
	// Adapters clear their copy before returning. The runner must still be able
	// to scrub the returned output and error using its private redaction copy.
	materialized.Clear()
	return SandboxResult{ExitCode: -1, Stdout: secret, Stderr: secret, ErrorText: string(secret)}, errors.New("sandbox failed: " + string(secret))
}

type fakeMaterializer struct {
	clearedValue []byte
	checkErr     error
}

func (m *fakeMaterializer) Check(context.Context, string, string, int, []string) error {
	return m.checkErr
}

func (m *fakeMaterializer) Materialize(context.Context, string, string, int, int, []string) (CredentialMaterialization, error) {
	value := []byte("runner-secret")
	m.clearedValue = value
	return CredentialMaterialization{Bindings: []CredentialBinding{{CredentialID: "cred_api", Environment: CredentialEnvironmentName("cred_api"), Value: value}}}, nil
}

func TestRunnerExecutesAdmittedStepWithoutPostSuccessCancellationFailure(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":1,"expected_exit_code":0}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	receipt := commandautomations.EvaluateExecutionGates(d, caps)
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_1", 1, digestHex, receipt)
	fj := &fakeJournal{
		definition: journal.CommandAutomationVersion{AutomationID: "cmd_1", Version: 1, DefinitionJSON: normalized},
		automation: journal.CommandAutomation{ID: "cmd_1", TenantID: "acme", Target: "local", Enabled: true},
	}
	fs := &fakeSandbox{}
	r := &Runner{
		Journal: fj, Sandbox: fs, Enabled: true,
		TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }),
		CapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
			return caps, nil
		},
		ActorProvider: func(context.Context) (string, error) { return "alice", nil },
	}
	result, err := r.Execute(context.Background(), Request{
		TenantID: "acme", AutomationID: "cmd_1", Version: 1, WorkerID: "worker", LeaseTTL: 5 * time.Second,
		Admission: journal.CommandRunAdmission{ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, DefinitionSHA256: digestHex, ActorID: "alice"},
	})
	if err != nil {
		t.Fatalf("runner execution failed: %v", err)
	}
	if result.Status != journal.CommandRunSucceeded || fj.finished != journal.CommandRunSucceeded || !fj.recorded || fs.calls != 1 {
		t.Fatalf("result=%+v finished=%q recorded=%v calls=%d", result, fj.finished, fj.recorded, fs.calls)
	}
}

func TestRunnerLeavesClaimRecoverableOnContextCancellation(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":5,"expected_exit_code":0}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	receipt := commandautomations.EvaluateExecutionGates(d, caps)
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_cancel", 1, digestHex, receipt)
	fj := &fakeJournal{
		definition: journal.CommandAutomationVersion{AutomationID: "cmd_cancel", Version: 1, DefinitionJSON: normalized},
		automation: journal.CommandAutomation{ID: "cmd_cancel", TenantID: "acme", Target: "local", Enabled: true},
	}
	fs := &blockingSandbox{started: make(chan struct{})}
	r := &Runner{
		Journal: fj, Sandbox: fs, Enabled: true,
		TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }),
		CapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
			return caps, nil
		},
		ActorProvider: func(context.Context) (string, error) { return "alice", nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan struct {
		result Result
		err    error
	}, 1)
	go func() {
		result, runErr := r.Execute(ctx, Request{
			TenantID: "acme", AutomationID: "cmd_cancel", Version: 1, WorkerID: "worker", LeaseTTL: 10 * time.Second,
			Admission: journal.CommandRunAdmission{ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, DefinitionSHA256: digestHex, ActorID: "alice"},
		})
		resultCh <- struct {
			result Result
			err    error
		}{result: result, err: runErr}
	}()
	select {
	case <-fs.started:
	case <-time.After(time.Second):
		t.Fatal("sandbox did not start")
	}
	cancel()
	select {
	case got := <-resultCh:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("context cancellation error = %v, want context.Canceled", got.err)
		}
		if fj.finished != "" || fj.run.Status != journal.CommandRunRunning {
			t.Fatalf("context cancellation terminalized claim: finished=%q run_status=%q result=%+v", fj.finished, fj.run.Status, got.result)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not return after context cancellation")
	}
}

type targetPolicyFunc func(context.Context, string, string) (bool, error)

func (f targetPolicyFunc) Allow(ctx context.Context, tenantID, target string) (bool, error) {
	return f(ctx, tenantID, target)
}

func TestRunnerRequiresTrustedCapabilitiesProvider(t *testing.T) {
	r := &Runner{Journal: &fakeJournal{}, Enabled: true, Sandbox: &fakeSandbox{}, TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }), ActorProvider: func(context.Context) (string, error) { return "alice", nil }}
	_, err := r.Execute(context.Background(), Request{TenantID: "acme", AutomationID: "cmd_1", Version: 1, WorkerID: "worker", LeaseTTL: time.Second})
	if !errors.Is(err, ErrRunnerUnavailable) {
		t.Fatalf("missing capability provider error = %v, want ErrRunnerUnavailable", err)
	}
}

func TestRunnerRefusesDisabledAutomationBeforeCreatingRun(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":1,"expected_exit_code":0}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: false, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_disabled", 1, digestHex, commandautomations.EvaluateExecutionGates(d, caps))
	fj := &fakeJournal{definition: journal.CommandAutomationVersion{AutomationID: "cmd_disabled", Version: 1, DefinitionJSON: normalized}, automation: journal.CommandAutomation{ID: "cmd_disabled", TenantID: "acme", Target: "local", Enabled: false}}
	fs := &fakeSandbox{}
	r := &Runner{Journal: fj, Sandbox: fs, Enabled: true, TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }), CapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
		return caps, nil
	}, ActorProvider: func(context.Context) (string, error) { return "alice", nil }}
	_, err = r.Execute(context.Background(), Request{TenantID: "acme", AutomationID: "cmd_disabled", Version: 1, WorkerID: "worker", LeaseTTL: 5 * time.Second, Admission: journal.CommandRunAdmission{ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, DefinitionSHA256: digestHex, ActorID: "alice"}})
	if !errors.Is(err, ErrBlocked) || fs.calls != 0 || fj.run.ID != "" {
		t.Fatalf("disabled execution err=%v calls=%d run=%+v", err, fs.calls, fj.run)
	}
}

func TestRunnerMaterializesAndScrubsCredentialOutput(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"use-secret","command":"printf %s \"$REACTOR_CREDENTIAL\"","purpose":"Use grant","timeout_seconds":1,"expected_exit_code":0,"credential_ids":["cred_api"]}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	receipt := commandautomations.EvaluateExecutionGates(d, caps)
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_secret", 1, digestHex, receipt)
	fj := &fakeJournal{definition: journal.CommandAutomationVersion{AutomationID: "cmd_secret", Version: 1, DefinitionJSON: normalized}, automation: journal.CommandAutomation{ID: "cmd_secret", TenantID: "acme", Target: "local", Enabled: true}}
	fs := &fakeSandbox{}
	mat := &fakeMaterializer{}
	r := &Runner{Journal: fj, Sandbox: fs, Enabled: true, CredentialMaterializer: mat, TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }), CapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
		return caps, nil
	}, ActorProvider: func(context.Context) (string, error) { return "alice", nil }}
	result, err := r.Execute(context.Background(), Request{TenantID: "acme", AutomationID: "cmd_secret", Version: 1, WorkerID: "worker", LeaseTTL: 5 * time.Second, Admission: journal.CommandRunAdmission{ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, DefinitionSHA256: digestHex, ActorID: "alice"}})
	if err != nil || result.Status != journal.CommandRunSucceeded {
		t.Fatalf("credential runner result=%+v err=%v", result, err)
	}
	if strings.Contains(string(fj.stdout), "runner-secret") || strings.Contains(string(fj.stderr), "runner-secret") || strings.Contains(fj.errText, "runner-secret") {
		t.Fatalf("credential leaked into journal output: stdout=%q stderr=%q err=%q", fj.stdout, fj.stderr, fj.errText)
	}
	if fs.calls != 1 {
		t.Fatalf("credential sandbox calls=%d, want 1", fs.calls)
	}
	if len(mat.clearedValue) != len("runner-secret") || strings.Trim(string(mat.clearedValue), "\x00") != "" {
		t.Fatalf("materialized value was not cleared: %v", mat.clearedValue)
	}
}

func TestExecuteSandboxScrubsErrorAfterAdapterClearsCredentials(t *testing.T) {
	secret := []byte("short-secret")
	wantSecret := string(secret)
	materialized := CredentialMaterialization{Bindings: []CredentialBinding{{CredentialID: "cred_api", Environment: CredentialEnvironmentName("cred_api"), Value: secret}}}
	r := &Runner{Sandbox: clearingErrorSandbox{}}
	result, err := r.executeSandbox(context.Background(), SandboxRequest{CredentialIDs: []string{"cred_api"}}, materialized)
	if err == nil {
		t.Fatal("credential sandbox unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), wantSecret) || strings.Contains(string(result.Stdout), wantSecret) || strings.Contains(string(result.Stderr), wantSecret) || strings.Contains(result.ErrorText, wantSecret) {
		t.Fatalf("credential leaked after adapter cleanup: err=%q stdout=%q stderr=%q error_text=%q", err, result.Stdout, result.Stderr, result.ErrorText)
	}
	if string(result.Stdout) != "[REDACTED]" || string(result.Stderr) != "[REDACTED]" || result.ErrorText != "[REDACTED]" {
		t.Fatalf("unexpected redaction result: %+v", result)
	}
	if result.StdoutBytes != len(result.Stdout) || result.StderrBytes != len(result.Stderr) {
		t.Fatalf("redacted output metadata is inconsistent: stdout_bytes=%d stderr_bytes=%d result=%+v", result.StdoutBytes, result.StderrBytes, result)
	}
}

type outputChunk struct {
	stream OutputStream
	data   []byte
}

type fakeOutputAppender struct {
	chunks []outputChunk
}

func (f *fakeOutputAppender) AppendCommandRunStepOutput(_ context.Context, _, _, _ string, _, _ int, stream string, data []byte) error {
	f.chunks = append(f.chunks, outputChunk{stream: OutputStream(stream), data: append([]byte(nil), data...)})
	return nil
}

func TestCredentialOutputSinkRedactsSplitSecretAndPersistsPartialChunks(t *testing.T) {
	appender := &fakeOutputAppender{}
	sink := newCredentialOutputSink(context.Background(), appender, "run", "worker", "claim", 1, 1, []CredentialBinding{{Value: []byte("split-secret")}})
	if err := sink.Write(OutputStdout, []byte("prefix split-")); err != nil {
		t.Fatal(err)
	}
	if len(appender.chunks) == 0 {
		t.Fatal("first output chunk was not persisted")
	}
	if err := sink.Write(OutputStdout, []byte("secret suffix")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	var combined []byte
	for _, chunk := range appender.chunks {
		if chunk.stream == OutputStdout {
			combined = append(combined, chunk.data...)
		}
	}
	if strings.Contains(string(combined), "split-secret") || !strings.Contains(string(combined), "[REDACTED]") || !strings.Contains(string(combined), "prefix") || !strings.Contains(string(combined), "suffix") {
		t.Fatalf("stream output was not safely redacted: %q", combined)
	}
}

type streamingCredentialSandbox struct {
	calls int
}

func (s *streamingCredentialSandbox) Profile() SandboxProfile {
	return SandboxProfile{Name: "stream-test", NonRoot: true, NoHostMounts: true, NetworkDisabled: true, ReadOnlyRoot: true, ResourceLimited: true, MaxOutputBytes: 1024}
}

func (s *streamingCredentialSandbox) Execute(context.Context, SandboxRequest) (SandboxResult, error) {
	return SandboxResult{ExitCode: 0}, nil
}

func (s *streamingCredentialSandbox) ExecuteWithCredentials(context.Context, SandboxRequest, CredentialMaterialization) (SandboxResult, error) {
	return SandboxResult{ExitCode: 0}, nil
}

func (s *streamingCredentialSandbox) ExecuteWithCredentialsStreaming(_ context.Context, _ SandboxRequest, _ CredentialMaterialization, sink OutputSink) (SandboxResult, error) {
	s.calls++
	if err := sink.Write(OutputStdout, []byte("prefix runner-")); err != nil {
		return SandboxResult{ExitCode: -1}, err
	}
	if err := sink.Write(OutputStdout, []byte("secret suffix")); err != nil {
		return SandboxResult{ExitCode: -1}, err
	}
	return SandboxResult{ExitCode: 0, Stdout: []byte("prefix runner-secret suffix")}, nil
}

type streamingFakeJournal struct {
	*fakeJournal
	appender *fakeOutputAppender
}

func (j *streamingFakeJournal) AppendCommandRunStepOutput(ctx context.Context, runID, workerID, claimToken string, stepSeq, attempt int, stream string, data []byte) error {
	return j.appender.AppendCommandRunStepOutput(ctx, runID, workerID, claimToken, stepSeq, attempt, stream, data)
}

func TestRunnerStreamsPartialCredentialOutputThroughRedactingSink(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"use-secret","command":"printf %s","purpose":"Stream","timeout_seconds":1,"expected_exit_code":0,"credential_ids":["cred_api"]}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	receipt := commandautomations.EvaluateExecutionGates(d, caps)
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_stream_secret", 1, digestHex, receipt)
	base := &fakeJournal{definition: journal.CommandAutomationVersion{AutomationID: "cmd_stream_secret", Version: 1, DefinitionJSON: normalized}, automation: journal.CommandAutomation{ID: "cmd_stream_secret", TenantID: "acme", Target: "local", Enabled: true}}
	appender := &fakeOutputAppender{}
	fj := &streamingFakeJournal{fakeJournal: base, appender: appender}
	fs := &streamingCredentialSandbox{}
	r := &Runner{Journal: fj, Sandbox: fs, Enabled: true, CredentialMaterializer: &fakeMaterializer{}, TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }), CapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
		return caps, nil
	}, ActorProvider: func(context.Context) (string, error) { return "alice", nil }}
	result, err := r.Execute(context.Background(), Request{TenantID: "acme", AutomationID: "cmd_stream_secret", Version: 1, WorkerID: "worker", LeaseTTL: 5 * time.Second, Admission: journal.CommandRunAdmission{ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, DefinitionSHA256: digestHex, ActorID: "alice"}})
	if err != nil || result.Status != journal.CommandRunSucceeded {
		t.Fatalf("streaming credential run result=%+v err=%v", result, err)
	}
	if fs.calls != 1 || len(appender.chunks) == 0 {
		t.Fatalf("streaming sandbox calls=%d chunks=%d", fs.calls, len(appender.chunks))
	}
	var streamed []byte
	for _, chunk := range appender.chunks {
		if chunk.stream == OutputStdout {
			streamed = append(streamed, chunk.data...)
		}
	}
	if strings.Contains(string(streamed), "runner-secret") || !strings.Contains(string(streamed), "[REDACTED]") {
		t.Fatalf("credential leaked through live output: %q", streamed)
	}
	if strings.Contains(string(fj.stdout), "runner-secret") {
		t.Fatalf("credential leaked through final output: %q", fj.stdout)
	}
}

func TestRunnerRejectsCredentialReadinessBeforeCreatingRun(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"use-secret","command":"true","purpose":"Use grant","timeout_seconds":1,"expected_exit_code":0,"credential_ids":["cred_api"]}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_secret", 1, digestHex, commandautomations.EvaluateExecutionGates(d, caps))
	fj := &fakeJournal{
		definition: journal.CommandAutomationVersion{AutomationID: "cmd_secret", Version: 1, DefinitionJSON: normalized},
		automation: journal.CommandAutomation{ID: "cmd_secret", TenantID: "acme", Target: "local", Enabled: true},
	}
	fs := &fakeSandbox{}
	mat := &fakeMaterializer{checkErr: errors.New("missing command grant")}
	r := &Runner{Journal: fj, Sandbox: fs, Enabled: true, CredentialMaterializer: mat, TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }), CapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
		return caps, nil
	}, ActorProvider: func(context.Context) (string, error) { return "alice", nil }}
	_, err = r.Execute(context.Background(), Request{TenantID: "acme", AutomationID: "cmd_secret", Version: 1, WorkerID: "worker", LeaseTTL: 5 * time.Second, Admission: journal.CommandRunAdmission{ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, DefinitionSHA256: digestHex, ActorID: "alice"}})
	if !errors.Is(err, ErrCredentialBoundary) || fj.run.ID != "" || fs.calls != 0 {
		t.Fatalf("credential readiness was admitted: err=%v run=%+v sandbox_calls=%d", err, fj.run, fs.calls)
	}
}

func TestRunnerRejectsBrokerOnlyOAuthBeforeCreatingRun(t *testing.T) {
	raw := []byte(`{"steps":[{"name":"use-connection","command":"true","purpose":"Use connection","timeout_seconds":1,"expected_exit_code":0,"credential_ids":["oauth:conn"]}]}`)
	d, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	caps := commandautomations.ExecutionCapabilities{FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true, StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true, RunnerReady: true, TargetReady: true}
	binding := commandautomations.BindExecutionReceipt("acme", "cmd_connection", 1, digestHex, commandautomations.EvaluateExecutionGates(d, caps))
	fj := &fakeJournal{
		definition: journal.CommandAutomationVersion{AutomationID: "cmd_connection", Version: 1, DefinitionJSON: normalized},
		automation: journal.CommandAutomation{ID: "cmd_connection", TenantID: "acme", Target: "local", Enabled: true},
	}
	fs := &fakeSandbox{}
	resolver := &deniedRawOAuthResolver{}
	materializer := VaultCredentialMaterializer{
		Grants:      fakeCredentialGrants{allowed: map[string]bool{"oauth:conn": true}},
		Tenants:     fakeCredentialTenants{"oauth:conn": "acme"},
		OAuthTokens: resolver,
	}
	r := &Runner{Journal: fj, Sandbox: fs, Enabled: true, CredentialMaterializer: materializer, TargetPolicy: targetPolicyFunc(func(context.Context, string, string) (bool, error) { return true, nil }), CapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
		return caps, nil
	}, ActorProvider: func(context.Context) (string, error) { return "alice", nil }}
	_, err = r.Execute(context.Background(), Request{TenantID: "acme", AutomationID: "cmd_connection", Version: 1, WorkerID: "worker", LeaseTTL: 5 * time.Second, Admission: journal.CommandRunAdmission{ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest, DefinitionSHA256: digestHex, ActorID: "alice"}})
	if !errors.Is(err, ErrCredentialBoundary) || fj.run.ID != "" || fs.calls != 0 || resolver.rawCalls != 0 {
		t.Fatalf("broker-only OAuth was admitted: err=%v run=%+v sandbox_calls=%d raw_token_calls=%d", err, fj.run, fs.calls, resolver.rawCalls)
	}
}

func TestDeterministicRunIDBindsCompleteAdmission(t *testing.T) {
	admission := journal.CommandRunAdmission{
		ReceiptID:        "receipt_1",
		GateDigest:       "gate_1",
		DefinitionSHA256: "definition_1",
		ActorID:          "alice",
	}
	one := deterministicRunID("acme", "cmd_1", 3, admission)
	two := deterministicRunID("acme", "cmd_1", 3, admission)
	if one == "" || one != two || len(one) != len("cmdrun_"+"0123456789abcdef0123456789abcdef") {
		t.Fatalf("unstable deterministic run id: %q %q", one, two)
	}
	changed := admission
	changed.GateDigest = "gate_2"
	if deterministicRunID("acme", "cmd_1", 3, changed) == one {
		t.Fatal("changed admission reused deterministic run id")
	}
}

func TestRequiredLeaseTTLTracksLongestStepWithBoundedHeadroom(t *testing.T) {
	definition := commandautomations.Definition{Steps: []commandautomations.Step{{TimeoutSeconds: 30}, {TimeoutSeconds: 120}}}
	if got, want := requiredLeaseTTL(definition), 2*time.Minute+time.Minute; got != want {
		t.Fatalf("required lease = %s, want %s", got, want)
	}
	long := commandautomations.Definition{Steps: []commandautomations.Step{{TimeoutSeconds: 86400}}}
	if got := requiredLeaseTTL(long); got != 24*time.Hour {
		t.Fatalf("max lease = %s, want 24h", got)
	}
}
