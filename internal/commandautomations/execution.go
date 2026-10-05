package commandautomations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ExecutionCapabilities describes the independent operational gates that must
// be true before a command plan could be handed to a future runner. It is an
// input to the read-only preflight receipt; it never grants permission or
// executes a plan. The MCP daemon keeps this closed by default until every
// gate has an explicit, audited implementation.
type ExecutionCapabilities struct {
	FeatureEnabled   bool
	SingleTenant     bool
	AdminAuthorized  bool
	StepUpAuthorized bool
	// TriggerAuthorized is set only by a trusted internal scheduler after a
	// durable schedule authorization has been resolved. It is deliberately
	// separate from the interactive admin and step-up facts: an MCP caller
	// cannot supply it, and a scheduled run still re-evaluates every other
	// deployment, target, sandbox, credential, output, and audit gate.
	TriggerAuthorized bool
	// AutomationEnabled is the durable review-to-runtime state of the exact
	// command plan. It is separate from the daemon feature flag: an operator
	// may configure a runner without activating any stored plan.
	AutomationEnabled    bool
	SandboxProfileReady  bool
	VaultBoundaryReady   bool
	CredentialsSupported bool
	OutputLimitsReady    bool
	AuditReady           bool
	// RunnerReady records whether a separately configured command runner is
	// present behind the policy gates. It is deliberately not a policy gate:
	// read-only preflight can report all policy checks while remaining closed.
	RunnerReady bool
	// TargetReady is supplied only after the daemon's exact target allowlist
	// accepts the stored automation target. It is kept out of the displayed
	// policy-gate list so target descriptors never become a gate bypass token.
	TargetReady bool
}

// ExecutionGate is one independently evaluated safety boundary. Reasons are
// operator-facing diagnostics and deliberately contain no command text,
// credential identifiers, or secret values.
type ExecutionGate struct {
	Name   string `json:"name"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// ExecutionReceipt is a point-in-time readiness result. GatesReady describes
// the independent policy checks; execution is eligible only when the daemon
// also reports a separately configured runner.
type ExecutionReceipt struct {
	Status            string          `json:"status"`
	GatesReady        bool            `json:"gates_ready"`
	ExecutionEligible bool            `json:"execution_eligible"`
	Executable        bool            `json:"executable"`
	Gates             []ExecutionGate `json:"gates"`
	MissingGates      []string        `json:"missing_gates,omitempty"`
	Reason            string          `json:"reason"`
}

// ExecutionReceiptBinding is the non-authorizing identity a future runner can
// carry into durable admission. It binds one tenant, immutable plan version,
// normalized-definition digest, and point-in-time gate result together. The
// binding is deliberately only metadata: it contains no assertion, grant, or
// credential and cannot make the current non-executing surface runnable.
type ExecutionReceiptBinding struct {
	ReceiptID  string `json:"receipt_id"`
	GateDigest string `json:"gate_digest"`
}

// BindExecutionReceipt returns deterministic, secret-free identities for one
// preflight result. The canonical JSON inputs are domain-separated and include
// all receipt fields, so a future runner cannot accidentally reuse a receipt
// for another tenant, version, definition, or gate outcome.
func BindExecutionReceipt(tenantID, automationID string, version int, definitionSHA256 string, receipt ExecutionReceipt) ExecutionReceiptBinding {
	input := struct {
		BindingVersion   int              `json:"binding_version"`
		TenantID         string           `json:"tenant_id"`
		AutomationID     string           `json:"automation_id"`
		Version          int              `json:"version"`
		DefinitionSHA256 string           `json:"definition_sha256"`
		Receipt          ExecutionReceipt `json:"receipt"`
	}{
		BindingVersion:   1,
		TenantID:         tenantID,
		AutomationID:     automationID,
		Version:          version,
		DefinitionSHA256: definitionSHA256,
		Receipt:          receipt,
	}
	gateBytes, _ := json.Marshal(input)
	gateSum := sha256.Sum256(gateBytes)
	gateDigest := hex.EncodeToString(gateSum[:])
	return ExecutionReceiptBinding{
		ReceiptID:  ReceiptIDForGateDigest(tenantID, automationID, version, definitionSHA256, gateDigest),
		GateDigest: gateDigest,
	}
}

// ReceiptIDForGateDigest derives the identity of a gate binding without
// needing the full gate result. Durable admission can use it to reject a
// receipt ID paired with a different tenant, plan, version, definition, or
// gate digest. It does not establish that the gates passed or remain current.
func ReceiptIDForGateDigest(tenantID, automationID string, version int, definitionSHA256, gateDigest string) string {
	receiptInput := struct {
		BindingVersion   int    `json:"binding_version"`
		TenantID         string `json:"tenant_id"`
		AutomationID     string `json:"automation_id"`
		Version          int    `json:"version"`
		DefinitionSHA256 string `json:"definition_sha256"`
		GateDigest       string `json:"gate_digest"`
	}{
		BindingVersion:   1,
		TenantID:         tenantID,
		AutomationID:     automationID,
		Version:          version,
		DefinitionSHA256: definitionSHA256,
		GateDigest:       gateDigest,
	}
	receiptBytes, _ := json.Marshal(receiptInput)
	receiptSum := sha256.Sum256(receiptBytes)
	return "cmdpreflight_v1_" + hex.EncodeToString(receiptSum[:])
}

// EvaluateExecutionGates checks every safety boundary independently. The
// result is deterministic for the supplied capabilities and normalized
// definition, which makes it suitable for MCP review receipts and tests.
func EvaluateExecutionGates(definition Definition, caps ExecutionCapabilities) ExecutionReceipt {
	credentialRefs := 0
	for _, step := range definition.Steps {
		credentialRefs += len(step.CredentialIDs)
	}
	gates := []ExecutionGate{
		{Name: "feature_flag", Ready: caps.FeatureEnabled, Reason: "command execution is disabled by default"},
		{Name: "single_tenant", Ready: caps.SingleTenant, Reason: "command execution requires an explicit single-tenant deployment"},
		{Name: "admin_authorization", Ready: caps.AdminAuthorized || caps.TriggerAuthorized, Reason: "an administrator must authorize command execution"},
		{Name: "step_up_authorization", Ready: caps.StepUpAuthorized || caps.TriggerAuthorized, Reason: "a fresh MFA step-up assertion is required"},
		{Name: "automation_enabled", Ready: caps.AutomationEnabled, Reason: "the exact command automation version is disabled"},
		{Name: "fixed_sandbox_profile", Ready: caps.SandboxProfileReady, Reason: "a fixed non-root, no-mount, resource-limited sandbox is unavailable"},
		{Name: "vault_grant_boundary", Ready: caps.VaultBoundaryReady || credentialRefs == 0, Reason: "credential references require a grant-aware vault boundary"},
		{Name: "credential_support", Ready: caps.CredentialsSupported || credentialRefs == 0, Reason: "this runner does not support the plan's credential references"},
		{Name: "bounded_output", Ready: caps.OutputLimitsReady, Reason: "stdout and stderr limits are not configured"},
		{Name: "durable_audit", Ready: caps.AuditReady, Reason: "durable command run and step receipts are not configured"},
	}
	missing := make([]string, 0, len(gates))
	for i := range gates {
		if !gates[i].Ready {
			missing = append(missing, gates[i].Name)
		}
	}
	receipt := ExecutionReceipt{
		Status:            "blocked",
		GatesReady:        len(missing) == 0,
		ExecutionEligible: len(missing) == 0 && caps.RunnerReady && caps.TargetReady,
		Executable:        len(missing) == 0 && caps.RunnerReady && caps.TargetReady,
		Gates:             gates,
		MissingGates:      missing,
		Reason:            "command execution is not available on this Reactor surface",
	}
	if receipt.GatesReady && !caps.RunnerReady {
		receipt.Reason = "all reported safety gates are satisfied, but command execution is unavailable until a runner is configured"
	} else if receipt.GatesReady && !caps.TargetReady {
		receipt.Reason = "all reported safety gates are satisfied, but the automation target is outside the configured allowlist"
	} else if receipt.ExecutionEligible {
		receipt.Status = "ready"
		receipt.Reason = "all safety gates and the configured command runner are ready; admission must still be re-evaluated at dispatch"
	}
	return receipt
}
