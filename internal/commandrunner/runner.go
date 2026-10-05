// Package commandrunner owns the daemon-side admission and execution loop for
// command automations. It is deliberately separate from the MCP package: an
// MCP request can produce a plan or a preflight receipt, but only this package
// can hand an admitted immutable version to an explicitly configured sandbox.
//
// The runner never resolves secrets itself and never starts a host process.
// Sandbox implementations are responsible for their isolation profile. The
// built-in Docker implementation in docker.go is the only process-launching
// adapter and uses a fixed, no-mount, non-root profile.
package commandrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

var (
	ErrDisabled           = errors.New("commandrunner: command execution is disabled")
	ErrBlocked            = errors.New("commandrunner: command execution gates are not satisfied")
	ErrRunnerUnavailable  = errors.New("commandrunner: no valid sandbox runner is configured")
	ErrTargetNotAllowed   = errors.New("commandrunner: command automation target is not allowed")
	ErrCredentialBoundary = errors.New("commandrunner: credential grant boundary is unavailable")
	ErrAdmissionStale     = errors.New("commandrunner: admission receipt is stale or does not match the immutable version")
	ErrLeaseTooShort      = errors.New("commandrunner: worker lease is shorter than the command step timeout")
	ErrInvalidRequest     = errors.New("commandrunner: invalid execution request")
)

// Journal is the narrow durable contract required by Runner. Keeping this as
// an interface makes the admission and sequencing logic testable without
// exposing database handles to a sandbox implementation.
type Journal interface {
	GetCommandAutomation(context.Context, string, string) (journal.CommandAutomation, error)
	GetCommandAutomationVersion(context.Context, string, string, int) (journal.CommandAutomationVersion, error)
	CreateCommandRun(context.Context, string, string, string, int, journal.CommandRunAdmission) (journal.CommandRun, error)
	ClaimCommandRun(context.Context, string, string, time.Duration) (journal.CommandRun, error)
	VerifyCommandRunLease(context.Context, string, string, string) error
	ExtendCommandRunLease(context.Context, string, string, string, time.Duration) error
	ClaimCommandRunStep(context.Context, string, string, string, int) (journal.CommandRunStep, error)
	RecordCommandRunStepResult(context.Context, string, string, string, int, int, int, []byte, []byte, string) error
	FinishCommandRun(context.Context, string, string, string, string, string) error
	GetCommandRunForTenant(context.Context, string, string) (journal.CommandRun, error)
}

// SandboxProfile is a declaration of the isolation properties a runner
// provides. Runner checks the profile in addition to the preflight capability
// receipt, so a caller cannot claim that an arbitrary process adapter is a
// fixed sandbox merely by setting SandboxProfileReady.
type SandboxProfile struct {
	Name            string
	NonRoot         bool
	NoHostMounts    bool
	NetworkDisabled bool
	ReadOnlyRoot    bool
	ResourceLimited bool
	MaxOutputBytes  int
}

func (p SandboxProfile) Valid() bool {
	return strings.TrimSpace(p.Name) != "" && p.NonRoot && p.NoHostMounts &&
		p.NetworkDisabled && p.ReadOnlyRoot && p.ResourceLimited &&
		p.MaxOutputBytes > 0 && p.MaxOutputBytes <= journal.MaxCommandOutputBytes
}

// SandboxRequest is the only command-bearing value passed to a backend. A
// backend must keep command text inside its isolated process and must never
// log it. CredentialIDs are references, never plaintext values.
type SandboxRequest struct {
	TenantID      string
	AutomationID  string
	AutomationVer int
	Target        string
	StepSeq       int
	StepName      string
	Command       string
	WorkingDir    string
	ExpectedExit  int
	Timeout       time.Duration
	CredentialIDs []string
}

// CredentialBinding is one short-lived secret binding prepared by an
// authenticated, grant-aware materializer. Value is never persisted or
// included in a command-run receipt. Implementations must clear Value as soon
// as the sandbox returns.
type CredentialBinding struct {
	CredentialID string
	Environment  string
	Value        []byte
}

// CredentialMaterialization is the in-memory handoff between the vault
// boundary and a credential-capable sandbox. It intentionally has no JSON or
// String representation; callers must call Clear after the sandbox returns.
type CredentialMaterialization struct {
	Bindings []CredentialBinding
}

// Clear overwrites all materialized bytes and drops the binding slice. This is
// best-effort defense in depth; callers must still treat the process as
// holding secret material while Execute is in progress.
func (m *CredentialMaterialization) Clear() {
	if m == nil {
		return
	}
	for i := range m.Bindings {
		for j := range m.Bindings[i].Value {
			m.Bindings[i].Value[j] = 0
		}
		m.Bindings[i].Value = nil
	}
	m.Bindings = nil
}

// SandboxResult carries process-independent output. The journal performs the
// final redaction and bounded persistence; implementations should still cap
// capture at SandboxProfile.MaxOutputBytes.
type SandboxResult struct {
	ExitCode        int
	Stdout          []byte
	Stderr          []byte
	StdoutBytes     int
	StderrBytes     int
	StdoutTruncated bool
	StderrTruncated bool
	ErrorText       string
}

// OutputStream identifies the process stream delivered to an optional live
// output sink. Stream values are deliberately small and fixed so a sandbox
// cannot smuggle arbitrary metadata into the durable journal.
type OutputStream string

const (
	OutputStdout OutputStream = "stdout"
	OutputStderr OutputStream = "stderr"
)

// OutputSink receives bounded-in-time process output while a step is still
// running. Implementations must treat p as ephemeral and must not retain it.
// The sink is optional: older sandbox adapters continue to use Execute and
// persist their final bounded result exactly as before.
type OutputSink interface {
	Write(OutputStream, []byte) error
}

// StreamingSandbox is an optional extension for adapters that can deliver
// output before process exit. It is intentionally separate from Sandbox so
// existing fakes and external adapters remain source-compatible.
type StreamingSandbox interface {
	Sandbox
	ExecuteStreaming(context.Context, SandboxRequest, OutputSink) (SandboxResult, error)
}

type outputMetadataRecorder interface {
	RecordCommandRunStepResultWithMetadata(context.Context, string, string, string, int, int, int, []byte, []byte, string, journal.CommandOutputMetadata) error
}

// Sandbox executes one already-admitted step under a fixed profile. It must
// not use host mounts, host credentials, or inherited environment state.
type Sandbox interface {
	Profile() SandboxProfile
	Execute(context.Context, SandboxRequest) (SandboxResult, error)
}

// CredentialSandbox is an explicit extension for adapters that can deliver
// short-lived credential bindings without putting values in argv or the
// durable journal. A plain Sandbox remains credential-free.
type CredentialSandbox interface {
	Sandbox
	ExecuteWithCredentials(context.Context, SandboxRequest, CredentialMaterialization) (SandboxResult, error)
}

// CredentialStreamingSandbox combines credential delivery with the optional
// live-output path. Credential values remain in-memory only and are redacted
// by Runner before the sink reaches the journal.
type CredentialStreamingSandbox interface {
	CredentialSandbox
	ExecuteWithCredentialsStreaming(context.Context, SandboxRequest, CredentialMaterialization, OutputSink) (SandboxResult, error)
}

type commandOutputAppender interface {
	AppendCommandRunStepOutput(context.Context, string, string, string, int, int, string, []byte) error
}

// credentialOutputSink keeps a short suffix per stream so a credential split
// across two writes is still redacted before durable append. It serializes
// writes because stdout and stderr may be copied concurrently by os/exec.
type credentialOutputSink struct {
	ctx       context.Context
	appender  commandOutputAppender
	runID     string
	workerID  string
	claim     string
	stepSeq   int
	attempt   int
	secrets   [][]byte
	maxSecret int
	mu        sync.Mutex
	pending   map[OutputStream][]byte
	err       error
}

func newCredentialOutputSink(ctx context.Context, appender commandOutputAppender, runID, workerID, claim string, stepSeq, attempt int, bindings []CredentialBinding) *credentialOutputSink {
	values := credentialRedactionValues(bindings)
	maxSecret := 0
	for _, value := range values {
		if len(value) > maxSecret {
			maxSecret = len(value)
		}
	}
	return &credentialOutputSink{ctx: ctx, appender: appender, runID: runID, workerID: workerID, claim: claim, stepSeq: stepSeq, attempt: attempt, secrets: values, maxSecret: maxSecret, pending: make(map[OutputStream][]byte)}
}

func (s *credentialOutputSink) Write(stream OutputStream, p []byte) error {
	if s == nil || len(p) == 0 {
		return nil
	}
	if stream != OutputStdout && stream != OutputStderr {
		return errors.New("commandrunner: invalid output stream")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	combined := append(append([]byte(nil), s.pending[stream]...), p...)
	// Keep a full secret-length suffix. Holding m bytes ensures a secret that
	// starts at the flush boundary cannot be split into two durable chunks.
	hold := s.maxSecret
	flushLen := len(combined) - hold
	if flushLen < 0 {
		flushLen = 0
	}
	flushLen = safeCredentialPrefixLen(combined, flushLen, s.secrets)
	if flushLen > 0 {
		out := append([]byte(nil), combined[:flushLen]...)
		for _, secret := range s.secrets {
			out = redactCredentialBytes(out, secret)
		}
		if err := s.appender.AppendCommandRunStepOutput(s.ctx, s.runID, s.workerID, s.claim, s.stepSeq, s.attempt, string(stream), out); err != nil {
			s.err = err
			return err
		}
	}
	s.pending[stream] = append(s.pending[stream][:0], combined[flushLen:]...)
	return nil
}

// safeCredentialPrefixLen backs a flush boundary away from a partial secret
// prefix. Holding only a fixed suffix is insufficient when that suffix begins
// with the tail of a secret and the flushed prefix ends with its beginning.
func safeCredentialPrefixLen(data []byte, candidate int, secrets [][]byte) int {
	if candidate <= 0 || len(secrets) == 0 {
		return maxInt(candidate, 0)
	}
	if candidate > len(data) {
		candidate = len(data)
	}
	for _, secret := range secrets {
		base := candidate
		keep := 0
		for n := 1; n < len(secret) && n <= candidate; n++ {
			if bytes.HasSuffix(data[:base], secret[:n]) && n > keep {
				keep = n
			}
		}
		candidate -= keep
	}
	if candidate < 0 {
		return 0
	}
	return candidate
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *credentialOutputSink) Flush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The sink owns copies of credential values so it can redact output that
	// crosses a pipe-write boundary. Clear those copies on every exit path,
	// including a fenced journal append failure.
	defer func() {
		clearCredentialRedactionValues(s.secrets)
		for stream, pending := range s.pending {
			for i := range pending {
				pending[i] = 0
			}
			s.pending[stream] = nil
		}
	}()
	if s.err != nil {
		return s.err
	}
	for _, stream := range []OutputStream{OutputStdout, OutputStderr} {
		pending := s.pending[stream]
		if len(pending) == 0 {
			continue
		}
		out := append([]byte(nil), pending...)
		for _, secret := range s.secrets {
			out = redactCredentialBytes(out, secret)
		}
		if err := s.appender.AppendCommandRunStepOutput(s.ctx, s.runID, s.workerID, s.claim, s.stepSeq, s.attempt, string(stream), out); err != nil {
			s.err = err
			return err
		}
		for i := range pending {
			pending[i] = 0
		}
		s.pending[stream] = nil
	}
	return nil
}

// Clear releases pending output and secret copies on every return path,
// including an append failure that prevents Flush from running to completion.
func (s *credentialOutputSink) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pending := range s.pending {
		for i := range pending {
			pending[i] = 0
		}
	}
	for i := range s.pending {
		delete(s.pending, i)
	}
	clearCredentialRedactionValues(s.secrets)
	s.secrets = nil
}

// CredentialMaterializer resolves references only after the runner has
// admitted the exact immutable version and claimed a fenced run step. It must
// enforce tenant ownership and the command grant ACL, and must never log or
// return plaintext except in CredentialMaterialization.
type CredentialMaterializer interface {
	Materialize(context.Context, string, string, int, int, []string) (CredentialMaterialization, error)
}

// CredentialReadiness is an optional non-secret admission check for a
// materializer. Implementations should validate only tenant ownership,
// explicit command grants, and resolver availability; they must not return or
// persist plaintext. Runner invokes it before creating a durable run so a
// missing grant, tenant boundary, or configured resolver cannot leave behind
// a run that was never eligible for dispatch.
type CredentialReadiness interface {
	Check(context.Context, string, string, int, []string) error
}

// TargetPolicy is an explicit allowlist for the target descriptor stored on a
// command automation. A nil policy is fail-closed even for local Docker runs.
type TargetPolicy interface {
	Allow(context.Context, string, string) (bool, error)
}

// CredentialBoundary validates a step's credential references against an
// operator-managed grant ACL. It intentionally returns no secret. A future
// sandbox may use an opaque grant handle internally; plaintext must never
// enter SandboxRequest or the journal.
type CredentialBoundary interface {
	Authorize(context.Context, string, string, int, int, []string) error
}

// CommandGrantJournal is the minimal durable ACL query used by the default
// command boundary. It returns no credential material.
type CommandGrantJournal interface {
	HasCommandGrant(context.Context, string, string, string) (bool, error)
}

// JournalCredentialBoundary enforces one explicit command ACL row for every
// referenced credential. It intentionally does not resolve or transport a
// secret; adapters that need material must add a separate audited boundary.
type JournalCredentialBoundary struct{ Journal CommandGrantJournal }

func (b JournalCredentialBoundary) Authorize(ctx context.Context, tenantID, automationID string, _ int, _ int, credentialIDs []string) error {
	if b.Journal == nil {
		return ErrCredentialBoundary
	}
	for _, credentialID := range credentialIDs {
		ok, err := b.Journal.HasCommandGrant(ctx, tenantID, automationID, credentialID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("commandrunner: credential %q is not explicitly granted", credentialID)
		}
	}
	return nil
}

// ExactTargetPolicy is a small fail-closed target allowlist for the local
// runner. Target descriptors are data, so matching is exact and tenant-aware;
// remote/agent transports need a separate policy implementation.
type ExactTargetPolicy map[string]struct{}

func (p ExactTargetPolicy) Allow(_ context.Context, _ string, target string) (bool, error) {
	_, ok := p[strings.TrimSpace(target)]
	return ok, nil
}

// Request identifies one exact immutable command-automation version. The
// admission fields must have come from a fresh preflight receipt; Runner
// recomputes the receipt and refuses stale or forged bindings.
type Request struct {
	TenantID     string
	AutomationID string
	Version      int
	RunID        string
	// RetryOf links an explicit retry to a terminal source run. It is bounded
	// metadata only; command text, output, and credentials are never copied.
	RetryOf   string
	WorkerID  string
	LeaseTTL  time.Duration
	Admission journal.CommandRunAdmission
	// TriggerKind, TriggerID, and TriggerEventID are internal trigger
	// provenance. They are copied into the bounded admission receipt and
	// participate in deterministic run idempotency; MCP manual requests leave
	// them empty.
	TriggerKind    string
	TriggerID      string
	TriggerEventID string
}

// CapabilitiesProvider is a trusted daemon-side provider. It must derive
// feature, tenant, admin, step-up, sandbox, vault, output, and audit facts
// from authenticated server state; accepting those booleans from an MCP
// caller would turn preflight metadata into an authorization bypass.
type CapabilitiesProvider func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error)

// ScheduledCapabilitiesProvider supplies daemon-owned operational facts for a
// trusted schedule fire. Interactive admin and step-up state is intentionally
// absent from the scheduler context; Runner marks only those two gates as
// trigger-authorized after it has verified the durable schedule binding.
type ScheduledCapabilitiesProvider func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error)

// ActorProvider binds the durable admission actor to authenticated daemon
// state. A caller-supplied actor string is never sufficient for execution.
type ActorProvider func(context.Context) (string, error)

// Result is a bounded execution receipt. Command text and credentials are
// intentionally absent; callers can inspect the durable run through the
// tenant-scoped MCP read tools.
type Result struct {
	RunID   string
	Status  string
	Receipt commandautomations.ExecutionReceipt
	Run     journal.CommandRun
}

// Runner admits and executes one command automation. Enabled is an explicit
// daemon feature flag and remains false unless an operator opts into command
// execution. No default constructor enables it.
type Runner struct {
	Journal                       Journal
	Sandbox                       Sandbox
	TargetPolicy                  TargetPolicy
	CredentialBoundary            CredentialBoundary
	CredentialMaterializer        CredentialMaterializer
	CapabilitiesProvider          CapabilitiesProvider
	ScheduledCapabilitiesProvider ScheduledCapabilitiesProvider
	ActorProvider                 ActorProvider
	Enabled                       bool
}

// admissionState is the verified immutable plan and receipt produced before
// a durable command run is created. It contains no command output or secret
// material and can safely be carried from HTTP admission to a worker.
type admissionState struct {
	definition commandautomations.Definition
	digest     string
	receipt    commandautomations.ExecutionReceipt
	leaseTTL   time.Duration
}

// triggerAdmission is the runner's internal, receipt-bound view of an
// unattended trigger. It contains only tenant/plan identity and bounded
// provenance; the owning journal row remains the authority at final insert.
type triggerAdmission struct {
	kind             string
	id               string
	eventID          string
	sourceID         string
	definitionSHA256 string
	receiptID        string
	gateDigest       string
	actorID          string
}

// Admit performs the complete interactive admission path and creates a
// queued durable run without claiming it or starting a sandbox. The caller
// must enqueue the returned run for ExecuteQueued; a queued run is durable and
// may also be recovered by a later worker after process interruption.
func (r *Runner) Admit(ctx context.Context, req Request) (Result, error) {
	state, err := r.admit(ctx, req)
	if err != nil {
		return Result{}, err
	}
	req.LeaseTTL = state.leaseTTL
	run, err := r.createRun(ctx, req, state)
	if err != nil {
		return Result{Receipt: state.receipt}, err
	}
	return Result{RunID: run.ID, Status: run.Status, Receipt: state.receipt, Run: run}, nil
}

// AdmitScheduled admits one fire from a durable command schedule. The caller
// must be the internal scheduler and provide the exact schedule row it just
// loaded; MCP requests have no path to set TriggerAuthorized. Runner re-reads
// the immutable plan, recomputes operational gates, and compares the stored
// receipt binding before it creates a queued run.
func (r *Runner) AdmitScheduled(ctx context.Context, req Request, schedule journal.CommandAutomationSchedule) (Result, error) {
	if strings.TrimSpace(schedule.ID) == "" || strings.TrimSpace(schedule.TenantID) == "" || schedule.State != journal.CommandAutomationScheduleActive {
		return Result{}, ErrBlocked
	}
	if req.TenantID != schedule.TenantID || req.AutomationID != schedule.AutomationID || req.Version != schedule.AutomationVersion {
		return Result{}, ErrAdmissionStale
	}
	getter, ok := r.Journal.(interface {
		GetCommandAutomationScheduleForTenant(context.Context, string, string) (journal.CommandAutomationSchedule, error)
	})
	if !ok {
		return Result{}, ErrRunnerUnavailable
	}
	fresh, err := getter.GetCommandAutomationScheduleForTenant(ctx, req.TenantID, schedule.ID)
	if err != nil {
		return Result{}, fmt.Errorf("commandrunner: resolve scheduled admission: %w", err)
	}
	if fresh.Revision != schedule.Revision || fresh.State != journal.CommandAutomationScheduleActive || fresh.AutomationID != schedule.AutomationID || fresh.AutomationVersion != schedule.AutomationVersion || fresh.DefinitionSHA256 != schedule.DefinitionSHA256 || fresh.ReceiptID != schedule.ReceiptID || fresh.GateDigest != schedule.GateDigest || fresh.ActorID != schedule.ActorID || fresh.Spec != schedule.Spec || fresh.Timezone != schedule.Timezone {
		return Result{}, ErrAdmissionStale
	}
	schedule = fresh
	if strings.TrimSpace(req.TriggerID) == "" {
		req.TriggerID = schedule.ID
	}
	if req.TriggerID != schedule.ID || strings.TrimSpace(req.TriggerEventID) == "" {
		return Result{}, ErrInvalidRequest
	}
	// The scheduler is the trusted source of this metadata. Do not accept a
	// caller-provided admission or actor when the durable schedule has one.
	req.Admission = journal.CommandRunAdmission{
		ReceiptID: schedule.ReceiptID, GateDigest: schedule.GateDigest,
		DefinitionSHA256: schedule.DefinitionSHA256, ActorID: schedule.ActorID,
		TriggerKind: journal.CommandRunTriggerSchedule,
		TriggerID:   schedule.ID, TriggerEventID: req.TriggerEventID,
	}
	req.TriggerKind = journal.CommandRunTriggerSchedule
	req.WorkerID = "command-schedule-admission"
	state, err := r.admitWithSchedule(ctx, req, &schedule)
	if err != nil {
		return Result{Receipt: state.receipt}, err
	}
	req.LeaseTTL = state.leaseTTL
	run, err := r.createRun(ctx, req, state)
	if err != nil {
		return Result{Receipt: state.receipt}, err
	}
	return Result{RunID: run.ID, Status: run.Status, Receipt: state.receipt, Run: run}, nil
}

// AdmitWebhook admits one authenticated delivery for a dedicated command
// webhook. The receiver supplies only the trigger row and a bounded delivery
// identity after HMAC verification; Runner re-reads the row before creating a
// run and the journal fences the final insert against the active binding.
func (r *Runner) AdmitWebhook(ctx context.Context, req Request, trigger journal.CommandAutomationWebhookTrigger) (Result, error) {
	if trigger.State != journal.CommandAutomationWebhookActive || strings.TrimSpace(trigger.ID) == "" || strings.TrimSpace(trigger.TenantID) == "" {
		return Result{}, ErrBlocked
	}
	if req.TenantID != trigger.TenantID || req.AutomationID != trigger.AutomationID || req.Version != trigger.AutomationVersion || strings.TrimSpace(req.TriggerEventID) == "" {
		return Result{}, ErrAdmissionStale
	}
	getter, ok := r.Journal.(interface {
		GetCommandAutomationWebhookTriggerForTenant(context.Context, string, string) (journal.CommandAutomationWebhookTrigger, error)
	})
	if !ok {
		return Result{}, ErrRunnerUnavailable
	}
	fresh, err := getter.GetCommandAutomationWebhookTriggerForTenant(ctx, req.TenantID, trigger.ID)
	if err != nil {
		return Result{}, fmt.Errorf("commandrunner: resolve webhook admission: %w", err)
	}
	if fresh.State != journal.CommandAutomationWebhookActive || fresh.TenantID != trigger.TenantID || fresh.AutomationID != trigger.AutomationID || fresh.AutomationVersion != trigger.AutomationVersion || fresh.DefinitionSHA256 != trigger.DefinitionSHA256 || fresh.ReceiptID != trigger.ReceiptID || fresh.GateDigest != trigger.GateDigest || fresh.ActorID != trigger.ActorID || fresh.SecretID != trigger.SecretID || fresh.Provider != trigger.Provider {
		return Result{}, ErrAdmissionStale
	}
	return r.admitTriggered(ctx, req, triggerAdmission{
		kind: journal.CommandRunTriggerWebhook, id: fresh.ID, eventID: req.TriggerEventID,
		definitionSHA256: fresh.DefinitionSHA256, receiptID: fresh.ReceiptID, gateDigest: fresh.GateDigest, actorID: fresh.ActorID,
	})
}

// AdmitChain admits one terminal workflow event for a dedicated command
// chain. The terminal hook must derive EventID from the source run and status;
// callers cannot choose a different actor, plan, or receipt.
func (r *Runner) AdmitChain(ctx context.Context, req Request, trigger journal.CommandAutomationChainTrigger) (Result, error) {
	if trigger.State != journal.CommandAutomationChainActive || strings.TrimSpace(trigger.ID) == "" || strings.TrimSpace(trigger.TenantID) == "" {
		return Result{}, ErrBlocked
	}
	if req.TenantID != trigger.TenantID || req.AutomationID != trigger.AutomationID || req.Version != trigger.AutomationVersion || strings.TrimSpace(req.TriggerEventID) == "" {
		return Result{}, ErrAdmissionStale
	}
	getter, ok := r.Journal.(interface {
		GetCommandAutomationChainTriggerForTenant(context.Context, string, string) (journal.CommandAutomationChainTrigger, error)
	})
	if !ok {
		return Result{}, ErrRunnerUnavailable
	}
	fresh, err := getter.GetCommandAutomationChainTriggerForTenant(ctx, req.TenantID, trigger.ID)
	if err != nil {
		return Result{}, fmt.Errorf("commandrunner: resolve chain admission: %w", err)
	}
	if fresh.State != journal.CommandAutomationChainActive || fresh.TenantID != trigger.TenantID || fresh.AutomationID != trigger.AutomationID || fresh.AutomationVersion != trigger.AutomationVersion || fresh.DefinitionSHA256 != trigger.DefinitionSHA256 || fresh.ReceiptID != trigger.ReceiptID || fresh.GateDigest != trigger.GateDigest || fresh.ActorID != trigger.ActorID || fresh.SourceWorkflowID != trigger.SourceWorkflowID || fresh.OnStatuses != trigger.OnStatuses {
		return Result{}, ErrAdmissionStale
	}
	return r.admitTriggered(ctx, req, triggerAdmission{
		kind: journal.CommandRunTriggerChain, id: fresh.ID, eventID: req.TriggerEventID, sourceID: fresh.SourceWorkflowID,
		definitionSHA256: fresh.DefinitionSHA256, receiptID: fresh.ReceiptID, gateDigest: fresh.GateDigest, actorID: fresh.ActorID,
	})
}

func (r *Runner) admitTriggered(ctx context.Context, req Request, trigger triggerAdmission) (Result, error) {
	if trigger.kind == "" || trigger.id == "" || trigger.eventID == "" {
		return Result{}, ErrInvalidRequest
	}
	req.TriggerKind, req.TriggerID, req.TriggerEventID = trigger.kind, trigger.id, trigger.eventID
	req.Admission = journal.CommandRunAdmission{
		ReceiptID: trigger.receiptID, GateDigest: trigger.gateDigest, DefinitionSHA256: trigger.definitionSHA256,
		ActorID: trigger.actorID, TriggerKind: trigger.kind, TriggerID: trigger.id, TriggerEventID: trigger.eventID,
	}
	req.WorkerID = "command-trigger-admission"
	state, err := r.admitWithTriggerBinding(ctx, req, &trigger)
	if err != nil {
		return Result{Receipt: state.receipt}, err
	}
	req.LeaseTTL = state.leaseTTL
	run, err := r.createRun(ctx, req, state)
	if err != nil {
		return Result{Receipt: state.receipt}, err
	}
	return Result{RunID: run.ID, Status: run.Status, Receipt: state.receipt, Run: run}, nil
}

// Execute performs interactive admission and then immediately claims and
// executes the newly-created run. Existing idempotent rows are returned
// without reclaiming or replaying them; asynchronous callers use Admit and
// ExecuteQueued instead.
func (r *Runner) Execute(ctx context.Context, req Request) (Result, error) {
	state, err := r.admit(ctx, req)
	if err != nil {
		return Result{}, err
	}
	req.LeaseTTL = state.leaseTTL
	run, err := r.createRun(ctx, req, state)
	if err != nil {
		return Result{Receipt: state.receipt}, err
	}
	out := Result{RunID: run.ID, Receipt: state.receipt, Run: run}
	if !run.Created {
		out.Status = run.Status
		return out, nil
	}
	return r.executeClaimed(ctx, req, state.definition, run, out)
}

// ExecuteQueued claims and executes one run admitted by Admit. It deliberately
// does not re-run interactive admin/step-up checks: those checks were bound to
// the durable receipt at authenticated admission and the HTTP context no
// longer exists on a worker. Operational fences are rechecked against current
// durable state before a process can start (feature flag, current enabled
// version, target allowlist, immutable definition digest, and sandbox
// profile). Credential grants are revalidated by the materializer immediately
// before each credential-bearing step.
func (r *Runner) ExecuteQueued(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil || r.Journal == nil {
		return Result{}, ErrRunnerUnavailable
	}
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.AutomationID) == "" || req.Version < 1 || strings.TrimSpace(req.RunID) == "" || strings.TrimSpace(req.WorkerID) == "" {
		return Result{}, ErrInvalidRequest
	}
	if req.LeaseTTL < 0 || req.LeaseTTL > 24*time.Hour {
		return Result{}, ErrInvalidRequest
	}
	if !r.Enabled {
		return Result{}, ErrDisabled
	}
	if r.Sandbox == nil || !r.Sandbox.Profile().Valid() {
		return Result{}, ErrRunnerUnavailable
	}
	if r.TargetPolicy == nil {
		return Result{}, ErrTargetNotAllowed
	}
	run, err := r.Journal.GetCommandRunForTenant(ctx, req.TenantID, req.RunID)
	if err != nil {
		return Result{}, fmt.Errorf("commandrunner: resolve queued run: %w", err)
	}
	if run.ID != req.RunID || run.TenantID != req.TenantID || run.AutomationID != req.AutomationID || run.AutomationVersion != req.Version {
		return Result{}, ErrInvalidRequest
	}
	if run.Status != journal.CommandRunQueued && run.Status != journal.CommandRunRunning {
		return Result{RunID: run.ID, Status: run.Status, Run: run}, nil
	}
	if !sameAdmission(req.Admission, run.Admission) {
		return Result{}, ErrInvalidRequest
	}
	v, err := r.Journal.GetCommandAutomationVersion(ctx, req.TenantID, req.AutomationID, req.Version)
	if err != nil {
		return Result{}, fmt.Errorf("commandrunner: resolve queued immutable version: %w", err)
	}
	definition, normalized, err := commandautomations.Normalize(v.DefinitionJSON)
	if err != nil {
		return Result{}, fmt.Errorf("commandrunner: normalize queued immutable version: %w", err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	if digestHex != run.DefinitionSHA256 || digestHex != run.Admission.DefinitionSHA256 {
		return Result{}, ErrAdmissionStale
	}
	automation, err := r.Journal.GetCommandAutomation(ctx, req.TenantID, req.AutomationID)
	if err != nil {
		return Result{}, fmt.Errorf("commandrunner: resolve queued automation target: %w", err)
	}
	// A production journal always returns a positive current_version. Small
	// embedded test journals may omit that legacy field; the immutable version
	// and receipt checks below still bind the run in that compatibility case.
	if !automation.Enabled || (automation.CurrentVersion > 0 && automation.CurrentVersion != req.Version) {
		return Result{}, ErrBlocked
	}
	if err := r.authorizeTarget(ctx, req.TenantID, automation.Target); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(run.Admission.TriggerID) != "" {
		if err := r.validateTriggeredQueue(ctx, run, definition, digestHex, automation.Enabled); err != nil {
			return Result{}, err
		}
	}
	if req.LeaseTTL <= 0 {
		req.LeaseTTL = requiredLeaseTTL(definition)
	}
	if err := r.validateLease(req.LeaseTTL, definition); err != nil {
		return Result{}, err
	}
	// A queued run may have been admitted while a credential-capable sandbox
	// and materializer were configured, then recovered after either dependency
	// was removed or miswired. Keep the worker fail-closed at the dispatch
	// boundary instead of allowing executeClaimed to dereference a nil
	// materializer (or hand credential material to a credential-free adapter).
	if err := r.validateCredentialRuntime(definition); err != nil {
		return Result{}, err
	}
	// The receipt is already verified by CreateCommandRun. Keep its identity in
	// the result for observability even though the full gate projection is not
	// persisted in the journal.
	out := Result{RunID: run.ID, Status: run.Status, Run: run}
	return r.executeClaimed(ctx, req, definition, run, out)
}

// validateCredentialRuntime checks the dependencies that are not part of the
// immutable admission receipt. A durable queued row can outlive a process
// restart or an operator reconfiguration, so these checks must happen again
// immediately before a worker claims and executes it.
func (r *Runner) validateCredentialRuntime(definition commandautomations.Definition) error {
	for _, step := range definition.Steps {
		if len(step.CredentialIDs) == 0 {
			continue
		}
		if r == nil || r.CredentialMaterializer == nil {
			return ErrCredentialBoundary
		}
		if _, ok := r.Sandbox.(CredentialSandbox); !ok {
			return ErrCredentialBoundary
		}
	}
	return nil
}

func (r *Runner) validateTriggeredQueue(ctx context.Context, run journal.CommandRun, definition commandautomations.Definition, digestHex string, automationEnabled bool) error {
	triggerID := strings.TrimSpace(run.Admission.TriggerID)
	kind := strings.TrimSpace(run.Admission.TriggerKind)
	if kind == "" {
		kind = journal.CommandRunTriggerSchedule
	}
	if strings.TrimSpace(run.Admission.TriggerEventID) == "" {
		return ErrAdmissionStale
	}
	var (
		state, automationID, definitionSHA, receiptID, gateDigest, actorID string
		version                                                            int
	)
	var resolveErr error
	switch kind {
	case journal.CommandRunTriggerSchedule:
		getter, ok := r.Journal.(interface {
			GetCommandAutomationScheduleForTenant(context.Context, string, string) (journal.CommandAutomationSchedule, error)
		})
		if !ok {
			return ErrRunnerUnavailable
		}
		row, err := getter.GetCommandAutomationScheduleForTenant(ctx, run.TenantID, triggerID)
		if err != nil {
			resolveErr = fmt.Errorf("commandrunner: resolve scheduled admission: %w", err)
		} else {
			state, automationID, version, definitionSHA, receiptID, gateDigest, actorID = row.State, row.AutomationID, row.AutomationVersion, row.DefinitionSHA256, row.ReceiptID, row.GateDigest, row.ActorID
		}
	case journal.CommandRunTriggerWebhook:
		getter, ok := r.Journal.(interface {
			GetCommandAutomationWebhookTriggerForTenant(context.Context, string, string) (journal.CommandAutomationWebhookTrigger, error)
		})
		if !ok {
			return ErrRunnerUnavailable
		}
		row, err := getter.GetCommandAutomationWebhookTriggerForTenant(ctx, run.TenantID, triggerID)
		if err != nil {
			resolveErr = fmt.Errorf("commandrunner: resolve webhook admission: %w", err)
		} else {
			state, automationID, version, definitionSHA, receiptID, gateDigest, actorID = row.State, row.AutomationID, row.AutomationVersion, row.DefinitionSHA256, row.ReceiptID, row.GateDigest, row.ActorID
		}
	case journal.CommandRunTriggerChain:
		getter, ok := r.Journal.(interface {
			GetCommandAutomationChainTriggerForTenant(context.Context, string, string) (journal.CommandAutomationChainTrigger, error)
		})
		if !ok {
			return ErrRunnerUnavailable
		}
		row, err := getter.GetCommandAutomationChainTriggerForTenant(ctx, run.TenantID, triggerID)
		if err != nil {
			resolveErr = fmt.Errorf("commandrunner: resolve chain admission: %w", err)
		} else {
			state, automationID, version, definitionSHA, receiptID, gateDigest, actorID = row.State, row.AutomationID, row.AutomationVersion, row.DefinitionSHA256, row.ReceiptID, row.GateDigest, row.ActorID
		}
	default:
		return ErrAdmissionStale
	}
	if resolveErr != nil {
		return resolveErr
	}
	if state != "active" || automationID != run.AutomationID || version != run.AutomationVersion || definitionSHA != digestHex || receiptID != run.Admission.ReceiptID || gateDigest != run.Admission.GateDigest || actorID != run.Admission.ActorID {
		return ErrAdmissionStale
	}
	provider := r.ScheduledCapabilitiesProvider
	if provider == nil {
		return ErrRunnerUnavailable
	}
	caps, err := provider(ctx, definition)
	if err != nil {
		return fmt.Errorf("commandrunner: resolve triggered execution capabilities: %w", err)
	}
	caps.AutomationEnabled = automationEnabled
	caps.TargetReady = true
	caps.TriggerAuthorized = true
	current := commandautomations.EvaluateExecutionGates(definition, caps)
	binding := commandautomations.BindExecutionReceipt(run.TenantID, run.AutomationID, run.AutomationVersion, digestHex, current)
	if !current.GatesReady || !current.ExecutionEligible || binding.ReceiptID != run.Admission.ReceiptID || binding.GateDigest != run.Admission.GateDigest {
		return ErrAdmissionStale
	}
	return nil
}

// RejectQueued closes a durable queued run after ExecuteQueued reports a
// permanent admission or configuration failure. The queue calls this only
// for errors classified as non-retryable; database, lease, and sandbox
// failures remain queued for recovery. Claiming before finishing preserves
// the same owner/token fence used by normal execution and makes a concurrent
// recovery worker harmless.
func (r *Runner) RejectQueued(ctx context.Context, req Request, cause error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil || r.Journal == nil {
		return ErrRunnerUnavailable
	}
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.AutomationID) == "" || req.Version < 1 || strings.TrimSpace(req.RunID) == "" {
		return ErrInvalidRequest
	}
	workerID := strings.TrimSpace(req.WorkerID)
	if workerID == "" {
		workerID = "command-run-rejection"
	}
	run, err := r.Journal.GetCommandRunForTenant(ctx, req.TenantID, req.RunID)
	if err != nil {
		return fmt.Errorf("commandrunner: resolve queued run for rejection: %w", err)
	}
	// Rejection is itself the terminal safety action for a stale queue item.
	// Once the tenant and immutable run id are resolved, do not require the
	// obsolete automation/version/admission projection to match: those are the
	// exact facts that may have become stale, and leaving the row queued would
	// make the recovery poll retry a command that can never become safe.
	if run.Status != journal.CommandRunQueued {
		if run.Status == journal.CommandRunSucceeded || run.Status == journal.CommandRunFailed || run.Status == journal.CommandRunCancelled {
			return nil
		}
		return journal.ErrCommandRunNotClaimable
	}
	leaseTTL := req.LeaseTTL
	if leaseTTL <= 0 || leaseTTL > 24*time.Hour {
		leaseTTL = time.Minute
	}
	claimed, err := r.Journal.ClaimCommandRun(ctx, run.ID, workerID, leaseTTL)
	if err != nil {
		// ClaimCommandRun deliberately refuses disabled plans and stale current
		// versions at the execution boundary. Give journals that implement the
		// dedicated rejection primitive a way to close the still-queued row
		// without relaxing that kill-switch fence just to obtain a claim token.
		if errors.Is(err, journal.ErrCommandRunNotClaimable) || errors.Is(err, journal.ErrNotFound) {
			if rejector, ok := r.Journal.(interface {
				FailQueuedCommandRunForTenant(context.Context, string, string, string) error
			}); ok {
				rejectErr := rejector.FailQueuedCommandRunForTenant(ctx, req.TenantID, run.ID, queuedRejectionReason(cause))
				if rejectErr == nil {
					return nil
				}
				if errors.Is(rejectErr, journal.ErrNotFound) || errors.Is(rejectErr, journal.ErrCommandRunNotClaimable) || errors.Is(rejectErr, journal.ErrCommandRunOwnershipLost) {
					return rejectErr
				}
			}
		}
		return err
	}
	finishCtx, finishCancel := durableFinishContext(ctx)
	finishErr := r.Journal.FinishCommandRun(finishCtx, run.ID, workerID, claimed.ClaimToken, journal.CommandRunFailed, queuedRejectionReason(cause))
	finishCancel()
	if finishErr != nil {
		return fmt.Errorf("commandrunner: finish rejected queued run: %w", finishErr)
	}
	return nil
}

func queuedRejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrAdmissionStale), errors.Is(err, journal.ErrCommandRunDefinitionMismatch), errors.Is(err, journal.ErrCommandRunBindingMismatch), errors.Is(err, journal.ErrCommandRunConflict):
		return "command run admission receipt is stale or no longer matches the immutable version"
	case errors.Is(err, ErrCredentialBoundary):
		return "command run credential grant or resolver is no longer ready"
	case errors.Is(err, ErrTargetNotAllowed):
		return "command run target is no longer allowed"
	case errors.Is(err, ErrDisabled):
		return "command runner is disabled"
	case errors.Is(err, ErrBlocked):
		return "command automation is no longer dispatchable"
	case errors.Is(err, ErrRunnerUnavailable):
		return "command runner is unavailable"
	case errors.Is(err, ErrLeaseTooShort):
		return "command run lease is too short for the immutable plan"
	case errors.Is(err, ErrInvalidRequest):
		return "command run request is invalid"
	default:
		return "command run was rejected before execution"
	}
}

func (r *Runner) admit(ctx context.Context, req Request) (admissionState, error) {
	return r.admitWithTriggerBinding(ctx, req, nil)
}

func (r *Runner) admitWithSchedule(ctx context.Context, req Request, schedule *journal.CommandAutomationSchedule) (admissionState, error) {
	if schedule == nil {
		return r.admitWithTriggerBinding(ctx, req, nil)
	}
	return r.admitWithTriggerBinding(ctx, req, &triggerAdmission{
		kind: journal.CommandRunTriggerSchedule, id: schedule.ID, eventID: req.TriggerEventID,
		definitionSHA256: schedule.DefinitionSHA256, receiptID: schedule.ReceiptID,
		gateDigest: schedule.GateDigest, actorID: schedule.ActorID,
	})
}

func (r *Runner) admitWithTriggerBinding(ctx context.Context, req Request, trigger *triggerAdmission) (admissionState, error) {
	var state admissionState
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil || r.Journal == nil {
		return state, ErrRunnerUnavailable
	}
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.AutomationID) == "" || req.Version < 1 || strings.TrimSpace(req.WorkerID) == "" {
		return state, ErrInvalidRequest
	}
	if req.LeaseTTL < 0 || req.LeaseTTL > 24*time.Hour {
		return state, ErrInvalidRequest
	}
	if !r.Enabled {
		return state, ErrDisabled
	}
	if r.Sandbox == nil || !r.Sandbox.Profile().Valid() {
		return state, ErrRunnerUnavailable
	}
	if r.CapabilitiesProvider == nil && r.ScheduledCapabilitiesProvider == nil {
		return state, ErrRunnerUnavailable
	}
	if trigger != nil {
		if trigger.id == "" || trigger.eventID == "" || req.TriggerID != trigger.id || req.TriggerEventID != trigger.eventID {
			return state, ErrAdmissionStale
		}
	}
	v, err := r.Journal.GetCommandAutomationVersion(ctx, req.TenantID, req.AutomationID, req.Version)
	if err != nil {
		return state, fmt.Errorf("commandrunner: resolve immutable version: %w", err)
	}
	definition, normalized, err := commandautomations.Normalize(v.DefinitionJSON)
	if err != nil {
		return state, fmt.Errorf("commandrunner: normalize immutable version: %w", err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	automation, err := r.Journal.GetCommandAutomation(ctx, req.TenantID, req.AutomationID)
	if err != nil {
		return state, fmt.Errorf("commandrunner: resolve automation target: %w", err)
	}
	if err := r.authorizeTarget(ctx, req.TenantID, automation.Target); err != nil {
		return state, err
	}
	// Production journal rows always carry a positive current_version. Small
	// embedded test journals may omit that legacy field; immutable version and
	// receipt checks still bind the run in that compatibility case.
	if !automation.Enabled || (automation.CurrentVersion > 0 && automation.CurrentVersion != req.Version) {
		return state, ErrBlocked
	}
	var caps commandautomations.ExecutionCapabilities
	var capErr error
	if trigger != nil && r.ScheduledCapabilitiesProvider != nil {
		caps, capErr = r.ScheduledCapabilitiesProvider(ctx, definition)
	} else if r.CapabilitiesProvider != nil {
		caps, capErr = r.CapabilitiesProvider(ctx, definition)
	} else {
		return state, ErrRunnerUnavailable
	}
	if capErr != nil {
		return state, fmt.Errorf("commandrunner: resolve execution capabilities: %w", capErr)
	}
	caps.AutomationEnabled = automation.Enabled
	caps.TargetReady = true
	if trigger != nil {
		caps.TriggerAuthorized = true
	}
	receipt := commandautomations.EvaluateExecutionGates(definition, caps)
	leaseTTL := req.LeaseTTL
	if leaseTTL <= 0 {
		leaseTTL = requiredLeaseTTL(definition)
	}
	state = admissionState{definition: definition, digest: digestHex, receipt: receipt, leaseTTL: leaseTTL}
	if !receipt.GatesReady || !receipt.ExecutionEligible {
		if receipt.GatesReady && !receipt.ExecutionEligible {
			return state, fmt.Errorf("%w: runner is not ready", ErrBlocked)
		}
		return state, fmt.Errorf("%w: %s", ErrBlocked, strings.Join(receipt.MissingGates, ", "))
	}
	actor := strings.TrimSpace(req.Admission.ActorID)
	if trigger == nil {
		if r.ActorProvider == nil {
			return state, ErrRunnerUnavailable
		}
		var actorErr error
		actor, actorErr = r.ActorProvider(ctx)
		if actorErr != nil {
			return state, fmt.Errorf("commandrunner: resolve execution actor: %w", actorErr)
		}
		actor = strings.TrimSpace(actor)
	}
	if actor == "" || strings.IndexFunc(actor, unicode.IsControl) >= 0 {
		return state, ErrInvalidRequest
	}
	if trigger != nil {
		binding := commandautomations.BindExecutionReceipt(req.TenantID, req.AutomationID, req.Version, digestHex, receipt)
		if trigger.definitionSHA256 != digestHex || trigger.receiptID != binding.ReceiptID || trigger.gateDigest != binding.GateDigest || trigger.actorID != actor {
			return state, ErrAdmissionStale
		}
	}
	if err := r.validateLease(leaseTTL, definition); err != nil {
		return state, err
	}
	if err := r.validateAdmission(req, digestHex, receipt, actor); err != nil {
		return state, err
	}
	for _, step := range definition.Steps {
		if len(step.CredentialIDs) == 0 {
			continue
		}
		if r.CredentialMaterializer == nil && r.CredentialBoundary == nil {
			return state, ErrCredentialBoundary
		}
		if _, ok := r.Sandbox.(CredentialSandbox); !ok || r.CredentialMaterializer == nil {
			return state, ErrCredentialBoundary
		}
		if r.CredentialBoundary != nil {
			if err := r.CredentialBoundary.Authorize(ctx, req.TenantID, req.AutomationID, req.Version, 0, append([]string(nil), step.CredentialIDs...)); err != nil {
				return state, fmt.Errorf("%w: %v", ErrCredentialBoundary, err)
			}
		}
		if readiness, ok := r.CredentialMaterializer.(CredentialReadiness); ok {
			if err := readiness.Check(ctx, req.TenantID, req.AutomationID, req.Version, append([]string(nil), step.CredentialIDs...)); err != nil {
				return state, fmt.Errorf("%w: %v", ErrCredentialBoundary, err)
			}
		} else if r.CredentialBoundary == nil {
			return state, ErrCredentialBoundary
		}
	}
	return state, nil
}

func (r *Runner) createRun(ctx context.Context, req Request, state admissionState) (journal.CommandRun, error) {
	runID := strings.TrimSpace(req.RunID)
	if runID == "" {
		runID = deterministicRunID(req.TenantID, req.AutomationID, req.Version, req.Admission)
	}
	var (
		run journal.CommandRun
		err error
	)
	if retryOf := strings.TrimSpace(req.RetryOf); retryOf != "" {
		creator, ok := r.Journal.(interface {
			CreateCommandRunWithRetryOf(context.Context, string, string, string, int, journal.CommandRunAdmission, string) (journal.CommandRun, error)
		})
		if !ok {
			return journal.CommandRun{}, ErrInvalidRequest
		}
		run, err = creator.CreateCommandRunWithRetryOf(ctx, req.TenantID, runID, req.AutomationID, req.Version, req.Admission, retryOf)
	} else {
		run, err = r.Journal.CreateCommandRun(ctx, req.TenantID, runID, req.AutomationID, req.Version, req.Admission)
	}
	if err != nil {
		return journal.CommandRun{}, fmt.Errorf("commandrunner: create durable run: %w", err)
	}
	return run, nil
}

func sameAdmission(a, b journal.CommandRunAdmission) bool {
	return a.ReceiptID == b.ReceiptID && a.GateDigest == b.GateDigest && a.DefinitionSHA256 == b.DefinitionSHA256 && a.ActorID == b.ActorID && a.TriggerKind == b.TriggerKind && a.TriggerID == b.TriggerID && a.TriggerEventID == b.TriggerEventID
}

func (r *Runner) executeClaimed(ctx context.Context, req Request, definition commandautomations.Definition, run journal.CommandRun, out Result) (Result, error) {
	claimed, err := r.Journal.ClaimCommandRun(ctx, run.ID, req.WorkerID, req.LeaseTTL)
	if err != nil {
		return out, fmt.Errorf("commandrunner: claim durable run: %w", err)
	}
	out.Run = claimed
	if err := r.Journal.VerifyCommandRunLease(ctx, run.ID, req.WorkerID, claimed.ClaimToken); err != nil {
		return out, r.finishAfterError(ctx, run.ID, req.WorkerID, claimed.ClaimToken, err)
	}
	completed := map[int]bool{}
	if reader, ok := r.Journal.(interface {
		ListCommandRunStepsForTenant(context.Context, string, string) ([]journal.CommandRunStep, error)
	}); ok {
		steps, readErr := reader.ListCommandRunStepsForTenant(ctx, req.TenantID, run.ID)
		if readErr != nil {
			return out, r.finishAfterError(ctx, run.ID, req.WorkerID, claimed.ClaimToken, readErr)
		}
		for _, step := range steps {
			if step.Status == journal.CommandRunStepSucceeded {
				completed[step.StepSeq] = true
			}
		}
	}
	for i, step := range definition.Steps {
		seq := i + 1
		if completed[seq] {
			continue
		}
		if err := r.Journal.VerifyCommandRunLease(ctx, run.ID, req.WorkerID, claimed.ClaimToken); err != nil {
			return out, r.finishAfterError(ctx, run.ID, req.WorkerID, claimed.ClaimToken, err)
		}
		claimedStep, claimErr := r.Journal.ClaimCommandRunStep(ctx, run.ID, req.WorkerID, claimed.ClaimToken, seq)
		if claimErr != nil {
			return out, r.finishAfterError(ctx, run.ID, req.WorkerID, claimed.ClaimToken, claimErr)
		}
		materialized := CredentialMaterialization{}
		if len(step.CredentialIDs) > 0 {
			var materializeErr error
			materialized, materializeErr = r.CredentialMaterializer.Materialize(ctx, req.TenantID, req.AutomationID, req.Version, seq, append([]string(nil), step.CredentialIDs...))
			if materializeErr != nil {
				return out, r.finishAfterError(ctx, run.ID, req.WorkerID, claimed.ClaimToken, fmt.Errorf("%w: %v", ErrCredentialBoundary, materializeErr))
			}
		}
		stepCtx, cancel := context.WithTimeout(ctx, time.Duration(step.TimeoutSeconds)*time.Second)
		stepDone := make(chan struct{})
		leaseLost := make(chan error, 1)
		go r.heartbeat(ctx, stepDone, leaseLost, cancel, run.ID, req.WorkerID, claimed.ClaimToken, req.LeaseTTL)
		request := SandboxRequest{TenantID: req.TenantID, AutomationID: req.AutomationID, AutomationVer: req.Version, Target: run.Target, StepSeq: seq, StepName: step.Name, Command: step.Command, WorkingDir: step.WorkingDir, ExpectedExit: step.ExpectedExitCode, Timeout: time.Duration(step.TimeoutSeconds) * time.Second, CredentialIDs: append([]string(nil), step.CredentialIDs...)}
		var outputSink *credentialOutputSink
		if appender, ok := r.Journal.(commandOutputAppender); ok {
			outputSink = newCredentialOutputSink(stepCtx, appender, run.ID, req.WorkerID, claimed.ClaimToken, seq, claimedStep.Attempt, materialized.Bindings)
		}
		result, execErr := r.executeSandboxWithSink(stepCtx, request, materialized, outputSink)
		if outputSink != nil {
			flushErr := outputSink.Flush()
			outputSink.Clear()
			if execErr == nil && flushErr != nil {
				execErr = flushErr
			}
		}
		stepErr := stepCtx.Err()
		close(stepDone)
		cancel()
		select {
		case leaseErr := <-leaseLost:
			if execErr == nil {
				execErr = leaseErr
			}
		default:
		}
		errText := strings.TrimSpace(result.ErrorText)
		if execErr != nil && errText == "" {
			errText = execErr.Error()
		}
		exitCode := result.ExitCode
		if exitCode < -1 || exitCode > 255 {
			exitCode = -1
			if errText == "" {
				errText = "sandbox returned an invalid exit code"
			}
		}
		if stepErr != nil && errText == "" {
			errText = stepErr.Error()
		}
		// A request or daemon shutdown may cancel the execution context while
		// the sandbox is unwinding. Keep the step-result write alive long enough
		// to preserve bounded output, but do not turn that context cancellation
		// into a terminal operator cancellation. Explicit MCP cancellation
		// fences the durable row first; an unfenced context cancellation is an
		// infrastructure/request interruption and must remain recoverable by the
		// lease reaper.
		recordCtx, recordCancel := durableFinishContext(ctx)
		var recordErr error
		useMetadata := result.StdoutBytes > 0 || result.StderrBytes > 0 || result.StdoutTruncated || result.StderrTruncated || (len(result.Stdout) == 0 && len(result.Stderr) == 0)
		if recorder, ok := r.Journal.(outputMetadataRecorder); ok && useMetadata {
			recordErr = recorder.RecordCommandRunStepResultWithMetadata(recordCtx, run.ID, req.WorkerID, claimed.ClaimToken, seq, claimedStep.Attempt, exitCode, result.Stdout, result.Stderr, errText, journal.CommandOutputMetadata{StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes, StdoutTruncated: result.StdoutTruncated, StderrTruncated: result.StderrTruncated})
		} else {
			recordErr = r.Journal.RecordCommandRunStepResult(recordCtx, run.ID, req.WorkerID, claimed.ClaimToken, seq, claimedStep.Attempt, exitCode, result.Stdout, result.Stderr, errText)
		}
		recordCancel()
		if recordErr != nil {
			return out, r.finishAfterError(ctx, run.ID, req.WorkerID, claimed.ClaimToken, recordErr)
		}
		if ctx.Err() != nil {
			// The claim token and live lease are deliberately left intact. A
			// daemon shutdown or lost request must not destroy the only durable
			// recovery path; ReapExpiredCommandRunLeases will fence this worker
			// generation and requeue the run. reactor_cancel_command_run uses a
			// separate durable fence before interrupting a local worker, so an
			// explicit operator cancellation remains terminal.
			return out, ctx.Err()
		}
		if execErr != nil || errText != "" || exitCode != step.ExpectedExitCode {
			failure := errText
			if failure == "" {
				failure = fmt.Sprintf("step %q exited with code %d (expected %d)", step.Name, exitCode, step.ExpectedExitCode)
			}
			finishCtx, finishCancel := durableFinishContext(ctx)
			finishErr := r.Journal.FinishCommandRun(finishCtx, run.ID, req.WorkerID, claimed.ClaimToken, journal.CommandRunFailed, failure)
			finishCancel()
			if finishErr != nil {
				return out, finishErr
			}
			out.Status = journal.CommandRunFailed
			readCtx, readCancel := durableFinishContext(ctx)
			out.Run, _ = r.Journal.GetCommandRunForTenant(readCtx, req.TenantID, run.ID)
			readCancel()
			return out, nil
		}
	}
	finishCtx, finishCancel := durableFinishContext(ctx)
	finishErr := r.Journal.FinishCommandRun(finishCtx, run.ID, req.WorkerID, claimed.ClaimToken, journal.CommandRunSucceeded, "")
	finishCancel()
	if finishErr != nil {
		return out, fmt.Errorf("commandrunner: finish durable run: %w", finishErr)
	}
	out.Status = journal.CommandRunSucceeded
	readCtx, readCancel := durableFinishContext(ctx)
	out.Run, err = r.Journal.GetCommandRunForTenant(readCtx, req.TenantID, run.ID)
	readCancel()
	if err != nil {
		return out, fmt.Errorf("commandrunner: read terminal run: %w", err)
	}
	return out, nil
}

func (r *Runner) heartbeat(ctx context.Context, done <-chan struct{}, lost chan<- error, cancel context.CancelFunc, runID, workerID, token string, ttl time.Duration) {
	interval := ttl / 3
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Journal.ExtendCommandRunLease(ctx, runID, workerID, token, ttl); err != nil {
				cancel()
				select {
				case lost <- err:
				default:
				}
				return
			}
		}
	}
}

// executeSandbox keeps secret cleanup and exact-value output scrubbing at the
// runner boundary. Journal-level generic redaction remains defense in depth,
// but it cannot know a tenant's arbitrary vault value.
func (r *Runner) executeSandbox(ctx context.Context, request SandboxRequest, materialized CredentialMaterialization) (SandboxResult, error) {
	return r.executeSandboxWithSink(ctx, request, materialized, nil)
}

func (r *Runner) executeSandboxWithSink(ctx context.Context, request SandboxRequest, materialized CredentialMaterialization, sink OutputSink) (SandboxResult, error) {
	if len(request.CredentialIDs) > 0 && len(materialized.Bindings) == 0 {
		return SandboxResult{ExitCode: -1, ErrorText: ErrCredentialBoundary.Error()}, ErrCredentialBoundary
	}
	if len(materialized.Bindings) > 0 {
		if err := validateCredentialBindings(request.CredentialIDs, materialized.Bindings); err != nil {
			return SandboxResult{ExitCode: -1, ErrorText: ErrCredentialBoundary.Error()}, err
		}
	}
	// Keep a private copy of each value until output and error scrubbing is
	// complete. Credential-capable adapters are allowed (and encouraged) to
	// clear the materialization before returning, so relying on the adapter's
	// copy here would leave secrets in a result that is about to be journaled.
	redactionValues := credentialRedactionValues(materialized.Bindings)
	defer func() {
		clearCredentialRedactionValues(redactionValues)
		materialized.Clear()
	}()
	var (
		result SandboxResult
		err    error
	)
	if len(materialized.Bindings) > 0 {
		credentialSandbox, ok := r.Sandbox.(CredentialSandbox)
		if !ok {
			return SandboxResult{ExitCode: -1, ErrorText: ErrCredentialBoundary.Error()}, ErrCredentialBoundary
		}
		if streaming, ok := r.Sandbox.(CredentialStreamingSandbox); ok {
			result, err = streaming.ExecuteWithCredentialsStreaming(ctx, request, materialized, sink)
		} else {
			result, err = credentialSandbox.ExecuteWithCredentials(ctx, request, materialized)
		}
	} else {
		if streaming, ok := r.Sandbox.(StreamingSandbox); ok {
			result, err = streaming.ExecuteStreaming(ctx, request, sink)
		} else {
			result, err = r.Sandbox.Execute(ctx, request)
		}
	}
	for _, secret := range redactionValues {
		result.Stdout = redactCredentialBytes(result.Stdout, secret)
		result.Stderr = redactCredentialBytes(result.Stderr, secret)
		result.ErrorText = redactCredentialString(result.ErrorText, secret)
		err = redactCredentialError(err, secret)
	}
	// Replacing a short secret with the fixed marker can make the retained
	// output longer than the capture's original byte count. Keep metadata
	// internally consistent so the journal does not reject an otherwise safe
	// redacted result, and mark that visible output was bounded if needed.
	result = normalizeSandboxOutputMetadata(result)
	return result, err
}

func credentialRedactionValues(bindings []CredentialBinding) [][]byte {
	values := make([][]byte, 0, len(bindings))
	for _, binding := range bindings {
		if len(binding.Value) == 0 {
			continue
		}
		values = append(values, append([]byte(nil), binding.Value...))
	}
	return values
}

func clearCredentialRedactionValues(values [][]byte) {
	for _, value := range values {
		for i := range value {
			value[i] = 0
		}
	}
}

func redactCredentialError(err error, secret []byte) error {
	if err == nil || len(secret) == 0 {
		return err
	}
	redacted := redactCredentialString(err.Error(), secret)
	if redacted == err.Error() {
		return err
	}
	// Do not retain the original error as an unwrap target: callers that log
	// an error chain must not be able to recover the unsanitized message.
	return errors.New(redacted)
}

func normalizeSandboxOutputMetadata(result SandboxResult) SandboxResult {
	if result.StdoutBytes < len(result.Stdout) {
		result.StdoutBytes = len(result.Stdout)
	}
	if result.StderrBytes < len(result.Stderr) {
		result.StderrBytes = len(result.Stderr)
	}
	if result.StdoutBytes > journal.MaxCommandOutputBytes || len(result.Stdout) > journal.MaxCommandOutputBytes {
		result.StdoutTruncated = true
	}
	if result.StderrBytes > journal.MaxCommandOutputBytes || len(result.Stderr) > journal.MaxCommandOutputBytes {
		result.StderrTruncated = true
	}
	return result
}

func redactCredentialBytes(raw, secret []byte) []byte {
	if len(raw) == 0 || len(secret) == 0 {
		return raw
	}
	return bytes.ReplaceAll(raw, secret, []byte("[REDACTED]"))
}

func redactCredentialString(raw string, secret []byte) string {
	if raw == "" || len(secret) == 0 {
		return raw
	}
	return string(redactCredentialBytes([]byte(raw), secret))
}

func (r *Runner) authorizeTarget(ctx context.Context, tenantID, target string) error {
	// A nil policy is fail closed because target scope is security-sensitive.
	if r.TargetPolicy == nil {
		return ErrTargetNotAllowed
	}
	allowed, policyErr := r.TargetPolicy.Allow(ctx, tenantID, target)
	if policyErr != nil {
		return fmt.Errorf("commandrunner: target policy: %w", policyErr)
	}
	if !allowed {
		return ErrTargetNotAllowed
	}
	return nil
}

func (r *Runner) validateLease(ttl time.Duration, definition commandautomations.Definition) error {
	max := time.Duration(0)
	for _, step := range definition.Steps {
		if d := time.Duration(step.TimeoutSeconds) * time.Second; d > max {
			max = d
		}
	}
	if ttl <= max {
		return fmt.Errorf("%w: lease=%s max_step=%s", ErrLeaseTooShort, ttl, max)
	}
	return nil
}

// requiredLeaseTTL chooses a bounded lease for callers that leave the value
// unset (the HTTP queue does this because it admits the immutable definition
// before a worker claims it). A minute of headroom prevents a healthy step
// from being reaped while its process is still unwinding. The journal caps
// leases at 24 hours; a plan whose step itself is exactly 24 hours is therefore
// rejected by validateLease rather than being given an unsafe shorter lease.
func requiredLeaseTTL(definition commandautomations.Definition) time.Duration {
	maxStep := time.Second
	for _, step := range definition.Steps {
		if d := time.Duration(step.TimeoutSeconds) * time.Second; d > maxStep {
			maxStep = d
		}
	}
	const headroom = time.Minute
	if maxStep > 24*time.Hour-headroom {
		return 24 * time.Hour
	}
	return maxStep + headroom
}

func (r *Runner) validateAdmission(req Request, digest string, receipt commandautomations.ExecutionReceipt, actor string) error {
	binding := commandautomations.BindExecutionReceipt(req.TenantID, req.AutomationID, req.Version, digest, receipt)
	if req.Admission.DefinitionSHA256 != digest || req.Admission.GateDigest != binding.GateDigest || req.Admission.ReceiptID != binding.ReceiptID {
		return ErrAdmissionStale
	}
	if req.Admission.ActorID != actor {
		return ErrInvalidRequest
	}
	return nil
}

func (r *Runner) finishAfterError(ctx context.Context, runID, workerID, token string, cause error) error {
	if cause == nil {
		cause = errors.New("command runner failed")
	}
	// Cancellation fences the durable claim before the local worker context is
	// interrupted. Once that fence is visible, a late result or step error is
	// expected ownership loss; do not turn it into a retryable queue failure or
	// attempt a second terminal write with the stale token. An unfenced context
	// cancellation (for example daemon shutdown or a lost HTTP request) is also
	// recoverable: leave the live claim for the lease reaper instead of writing
	// a terminal cancellation from an infrastructure context.
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	finishCtx, finishCancel := durableFinishContext(ctx)
	status := journal.CommandRunFailed
	finishErr := r.Journal.FinishCommandRun(finishCtx, runID, workerID, token, status, cause.Error())
	finishCancel()
	if finishErr != nil {
		if ctx != nil && ctx.Err() != nil && errors.Is(finishErr, journal.ErrCommandRunOwnershipLost) {
			return ctx.Err()
		}
		return fmt.Errorf("%w; finish durable run: %v", cause, finishErr)
	}
	return cause
}

// durableFinishContext keeps terminal journal transitions possible after an
// HTTP request or sandbox context is cancelled. The caller's values remain
// available for tenant-scoped journal methods, while a short deadline keeps a
// stuck database from blocking the worker forever.
func durableFinishContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func deterministicRunID(tenantID, automationID string, version int, admission journal.CommandRunAdmission) string {
	material := strings.Join([]string{"cmdrun-v3", tenantID, automationID, fmt.Sprint(version), admission.ReceiptID, admission.GateDigest, admission.DefinitionSHA256, admission.ActorID, admission.TriggerKind, admission.TriggerID, admission.TriggerEventID}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return "cmdrun_" + hex.EncodeToString(sum[:16])
}
