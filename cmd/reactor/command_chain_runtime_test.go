package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/commandrunner"
	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

type commandChainTestSandbox struct{}

type commandChainRunnerStub struct {
	result   commandrunner.Result
	requests []commandrunner.Request
}

func (s *commandChainRunnerStub) AdmitChain(_ context.Context, req commandrunner.Request, _ journal.CommandAutomationChainTrigger) (commandrunner.Result, error) {
	s.requests = append(s.requests, req)
	return s.result, nil
}

type commandChainQueueStub struct {
	err      error
	requests []commandrunner.Request
}

func (s *commandChainQueueStub) Enqueue(_ context.Context, req commandrunner.Request) error {
	s.requests = append(s.requests, req)
	return s.err
}

func (commandChainTestSandbox) Profile() commandrunner.SandboxProfile {
	return commandrunner.SandboxProfile{
		Name: "command-chain-test", NonRoot: true, NoHostMounts: true,
		NetworkDisabled: true, ReadOnlyRoot: true, ResourceLimited: true,
		MaxOutputBytes: journal.MaxCommandOutputBytes,
	}
}

func (commandChainTestSandbox) Execute(context.Context, commandrunner.SandboxRequest) (commandrunner.SandboxResult, error) {
	return commandrunner.SandboxResult{ExitCode: 0}, nil
}

func TestCommandChainDispatcherFiresDeterministicallyAndFencesTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "command-chain-runtime.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbURL := "sqlite://" + dbPath
	if err := migrate.Up(ctx, log, dbURL); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)

	const tenant = "acme"
	const workflowID = "wf_command_chain_source"
	const sourceRunID = "run_command_chain_source"
	if err := j.CreateWorkflowInTenant(ctx, workflowID, "command-chain-source", "hash", "0.1.0", json.RawMessage(`{"steps":[]}`), tenant); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, sourceRunID, workflowID, "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, sourceRunID, journal.StatusSucceeded); err != nil {
		t.Fatal(err)
	}

	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`)
	plan, err := j.CreateCommandAutomation(ctx, tenant, "cmd_chain_runtime", "command-chain-runtime", "", "local", "chain-admin", definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, tenant, plan.ID, true, false, plan.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	normalizedDefinition, normalized, err := commandautomations.Normalize(definition)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(normalized)
	digest := hex.EncodeToString(digestBytes[:])
	caps := commandautomations.ExecutionCapabilities{
		FeatureEnabled: true, SingleTenant: true, SandboxProfileReady: true,
		VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true,
		AuditReady: true, RunnerReady: true, TargetReady: true,
		TriggerAuthorized: true, AutomationEnabled: true,
	}
	receipt := commandautomations.BindExecutionReceipt(tenant, plan.ID, plan.CurrentVersion, digest, commandautomations.EvaluateExecutionGates(normalizedDefinition, caps))
	trigger, err := j.CreateCommandAutomationChainTrigger(ctx, tenant, journal.CommandAutomationChainTriggerInput{
		ID: "cmdchain_runtime_trigger", AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256: digest, ReceiptID: receipt.ReceiptID, GateDigest: receipt.GateDigest,
		ActorID: "chain-admin", SourceWorkflowID: workflowID, OnStatuses: "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetCommandAutomationChainTriggerStateIfRevision(ctx, tenant, trigger.ID, journal.CommandAutomationChainActive, trigger.Revision); err != nil {
		t.Fatal(err)
	}
	trigger, err = j.GetCommandAutomationChainTriggerForTenant(ctx, tenant, trigger.ID)
	if err != nil {
		t.Fatal(err)
	}

	// A durable trigger must keep the source terminal effect retryable when a
	// restarted daemon has command-chain rows but command execution disabled.
	// Before the journal-backed adapter reported this runtime-unavailable error,
	// the terminal handler treated a nil adapter as "no chains" and acknowledged
	// the one-shot effect permanently.
	ev := dispatcher.TerminalEvent{RunID: sourceRunID, WorkflowID: workflowID, Status: journal.StatusSucceeded}
	unavailable := &commandChainDispatcher{Journal: j, TenantID: tenant, Log: log}
	handleRunTerminalWithCommandChains(ctx, log, nil, j, nil, nil, ev, unavailable)
	effects, err := j.ClaimTerminalEffects(ctx, 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(effects) != 1 || effects[0].RunID != sourceRunID {
		t.Fatalf("unavailable command-chain terminal effect = %+v, want one retryable receipt", effects)
	}
	if err := j.ReleaseTerminalEffectForClaim(ctx, effects[0], "asserting command-chain retryability"); err != nil {
		t.Fatalf("release terminal effect after assertion: %v", err)
	}
	stillActive, err := j.GetCommandAutomationChainTriggerForTenant(ctx, tenant, trigger.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stillActive.LastFiredAt != nil {
		t.Fatal("unavailable command-chain runtime acknowledged the trigger")
	}

	runner := &commandrunner.Runner{
		Journal: j, Sandbox: commandChainTestSandbox{}, Enabled: true,
		TargetPolicy: commandrunner.ExactTargetPolicy{"local": {}},
		ScheduledCapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
			return caps, nil
		},
	}
	queue, err := commandrunner.NewQueue(runner, j, commandrunner.QueueConfig{
		Workers: 1, Capacity: 1, PollInterval: time.Hour, TenantID: tenant, WorkerPrefix: "chain",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = queue.Stop(stopCtx)
	}()
	d := &commandChainDispatcher{Journal: j, Runner: runner, Queue: queue, TenantID: tenant, Log: log}
	// Once the runner is restored, replaying the same terminal effect admits
	// the chain and acknowledges the receipt.
	handleRunTerminalWithCommandChains(ctx, log, nil, j, nil, nil, ev, d)
	if err := d.FireCommandChains(ctx, ev); err != nil {
		t.Fatalf("first command chain fire: %v", err)
	}

	wantEventID := journal.CommandAutomationChainEventID(trigger.ID, sourceRunID, journal.StatusSucceeded)
	var run journal.CommandRun
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		run, err = findCommandChainRun(ctx, j, tenant, plan.ID)
		if err == nil && run.Status == journal.CommandRunSucceeded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if run.Admission.TriggerKind != journal.CommandRunTriggerChain || run.Admission.TriggerID != trigger.ID || run.Admission.TriggerEventID != wantEventID {
		t.Fatalf("command chain admission = %+v, want deterministic event %q", run.Admission, wantEventID)
	}

	// Replaying the same terminal event must resolve to the same durable run;
	// it must not create a second execution even though the trigger remains
	// active for future source runs.
	if err := d.FireCommandChains(ctx, ev); err != nil {
		t.Fatalf("replayed command chain fire: %v", err)
	}
	runs, err := j.ListCommandRunsForTenantPage(ctx, journal.CommandRunFilter{TenantID: tenant, AutomationID: plan.ID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != run.ID {
		t.Fatalf("replayed command chain runs = %#v, want one deterministic run %s", runs, run.ID)
	}
	marked, err := j.GetCommandAutomationChainTriggerForTenant(ctx, tenant, trigger.ID)
	if err != nil {
		t.Fatal(err)
	}
	if marked.LastFiredAt == nil {
		t.Fatal("command chain trigger was not marked fired")
	}

	// A full in-memory handoff is recoverable: the durable run already exists,
	// so the terminal path acknowledges the trigger and lets the queue recovery
	// poller pick it up later instead of reporting a duplicate side effect.
	stubRunner := &commandChainRunnerStub{result: commandrunner.Result{Run: journal.CommandRun{
		ID: "cmdrun_queue_full", Created: true, Status: journal.CommandRunQueued,
		Admission: journal.CommandRunAdmission{TriggerKind: journal.CommandRunTriggerChain, TriggerID: trigger.ID, TriggerEventID: wantEventID},
	}}}
	stubQueue := &commandChainQueueStub{err: commandrunner.ErrQueueFull}
	full := &commandChainDispatcher{Journal: j, Runner: stubRunner, Queue: stubQueue, TenantID: tenant, Log: log}
	if err := full.FireCommandChains(ctx, ev); err != nil {
		t.Fatalf("queue-full command chain fire: %v", err)
	}
	if len(stubRunner.requests) != 1 || len(stubQueue.requests) != 1 || !errors.Is(stubQueue.err, commandrunner.ErrQueueFull) {
		t.Fatalf("queue-full handoff runner=%#v queue=%#v", stubRunner.requests, stubQueue.requests)
	}
	if stubQueue.requests[0].TriggerEventID != wantEventID {
		t.Fatalf("queue-full event id = %q, want %q", stubQueue.requests[0].TriggerEventID, wantEventID)
	}

	// The dispatcher reads the source run's tenant and refuses a mismatched
	// configured tenant before it can enumerate or admit any trigger.
	foreign := &commandChainDispatcher{Journal: j, Runner: runner, Queue: queue, TenantID: "other", Log: log}
	if err := foreign.FireCommandChains(ctx, ev); err == nil {
		t.Fatal("foreign command-chain dispatcher accepted an acme source run")
	}
}

func findCommandChainRun(ctx context.Context, j *journal.Journal, tenantID, automationID string) (journal.CommandRun, error) {
	runs, err := j.ListCommandRunsForTenantPage(ctx, journal.CommandRunFilter{TenantID: tenantID, AutomationID: automationID, Limit: 10})
	if err != nil {
		return journal.CommandRun{}, err
	}
	if len(runs) == 0 {
		return journal.CommandRun{}, journal.ErrNotFound
	}
	return runs[0], nil
}
