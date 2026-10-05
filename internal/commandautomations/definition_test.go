package commandautomations

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeRejectsUnknownFieldsAndInlineSecrets(t *testing.T) {
	t.Parallel()
	base := `{"steps":[{"name":"check","command":"true","purpose":"Check host","timeout_seconds":30,"expected_exit_code":0}]}`
	if _, _, err := Normalize(json.RawMessage(base[:len(base)-1] + `,"extra":true}`)); err == nil {
		t.Fatal("unknown definition field accepted")
	}
	secret := `{"steps":[{"name":"check","command":"curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'","purpose":"Check host","timeout_seconds":30,"expected_exit_code":0}]}`
	if _, _, err := Normalize(json.RawMessage(secret)); err == nil || !strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("inline secret error = %v", err)
	}
}

func TestNormalizeRejectsDuplicateFieldsAndSetReferences(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"command":"false"}]}`,
		`{"tags":["ops","ops"],"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`,
		`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"credential_ids":["cred-1","cred-1"]}]}`,
	} {
		if _, _, err := Normalize(json.RawMessage(raw)); err == nil {
			t.Fatalf("ambiguous command definition accepted: %s", raw)
		}
	}
}

func TestNormalizeRejectsNestedDuplicateFields(t *testing.T) {
	t.Parallel()
	raw := `{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}],"metadata":{"a":1,"a":2}}`
	if _, _, err := Normalize(json.RawMessage(raw)); err == nil {
		t.Fatal("duplicate nested object field accepted")
	}
}

func TestNormalizeWorkingDirCanonicalizesSandboxPathsAndRejectsEscapes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty uses sandbox default", raw: "", want: ""},
		{name: "dot segments canonicalized", raw: "/workspace/./jobs/../checks", want: "/workspace/checks"},
		{name: "workspace root", raw: "/workspace", want: "/workspace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeWorkingDir(tc.raw)
			if err != nil || got != tc.want {
				t.Fatalf("NormalizeWorkingDir(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
			}
		})
	}
	for _, raw := range []string{"jobs", ".", "../host", "/tmp", "/workspace/../../host", "/workspace\n/jobs", " /workspace/jobs"} {
		if got, err := NormalizeWorkingDir(raw); err == nil {
			t.Fatalf("unsafe working_dir %q accepted as %q", raw, got)
		}
	}
	raw := json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"working_dir":"/workspace/jobs/../checks"}]}`)
	definition, normalized, err := Normalize(raw)
	if err != nil || definition.Steps[0].WorkingDir != "/workspace/checks" || !strings.Contains(string(normalized), `"working_dir":"/workspace/checks"`) {
		t.Fatalf("normalized definition working_dir = %+v, json=%s, err=%v", definition, normalized, err)
	}
}

func TestFlowIsDerivedFromOrderedSteps(t *testing.T) {
	t.Parallel()
	d, _, err := Normalize(json.RawMessage(`{"steps":[{"name":"prepare","command":"true","purpose":"Prepare","timeout_seconds":30,"expected_exit_code":0},{"name":"verify","command":"true","purpose":"Verify","timeout_seconds":30,"expected_exit_code":0}]}`))
	if err != nil {
		t.Fatal(err)
	}
	flow := d.Flow()
	if flow["executable"] != false {
		t.Fatalf("flow executable = %#v", flow["executable"])
	}
	nodes := flow["nodes"].([]map[string]any)
	edges := flow["edges"].([]map[string]any)
	if len(nodes) != 2 || nodes[0]["id"] != "prepare" || nodes[0]["command"] != "true" || nodes[0]["command_trust"] != "untrusted" || nodes[0]["timeout_seconds"] != 30 || len(edges) != 1 || edges[0]["from"] != "prepare" || edges[0]["to"] != "verify" {
		t.Fatalf("flow = %#v", flow)
	}
}

func TestCompareReportsStructuralChangesWithoutValues(t *testing.T) {
	t.Parallel()
	before, _, err := Normalize(json.RawMessage(`{"tags":["ops"],"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0},{"name":"verify","command":"true","purpose":"Verify","timeout_seconds":30,"expected_exit_code":0}]}`))
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := Normalize(json.RawMessage(`{"tags":["daily"],"steps":[{"name":"verify","command":"true","purpose":"Verify changed","timeout_seconds":30,"expected_exit_code":0},{"name":"report","command":"true","purpose":"Report","timeout_seconds":30,"expected_exit_code":0}]}`))
	if err != nil {
		t.Fatal(err)
	}
	diff := Compare(before, after)
	if diff.NoChanges || !diff.OrderChanged || len(diff.TagsAdded) != 1 || diff.TagsAdded[0] != "daily" || len(diff.TagsRemoved) != 1 || diff.TagsRemoved[0] != "ops" || len(diff.StepsAdded) != 1 || diff.StepsAdded[0] != "report" || len(diff.StepsRemoved) != 1 || diff.StepsRemoved[0] != "check" || len(diff.StepsChanged) != 1 || diff.StepsChanged[0].Name != "verify" || len(diff.StepsChanged[0].Fields) != 1 || diff.StepsChanged[0].Fields[0] != "purpose" {
		t.Fatalf("diff = %#v", diff)
	}
}

func TestEvaluateExecutionGatesIsClosedByDefault(t *testing.T) {
	t.Parallel()
	d, _, err := Normalize(json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"credential_ids":["cred-1"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	receipt := EvaluateExecutionGates(d, ExecutionCapabilities{})
	if receipt.Status != "blocked" || receipt.GatesReady || receipt.ExecutionEligible || receipt.Executable {
		t.Fatalf("closed receipt = %+v", receipt)
	}
	want := map[string]bool{"feature_flag": true, "single_tenant": true, "admin_authorization": true, "step_up_authorization": true, "automation_enabled": true, "fixed_sandbox_profile": true, "vault_grant_boundary": true, "credential_support": true, "bounded_output": true, "durable_audit": true}
	for _, name := range receipt.MissingGates {
		if !want[name] {
			t.Fatalf("unexpected missing gate %q in %+v", name, receipt)
		}
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("missing gates omitted %v from %+v", want, receipt)
	}
}

func TestEvaluateExecutionGatesReportsCredentialBoundaryAndReadyRunner(t *testing.T) {
	t.Parallel()
	d, _, err := Normalize(json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0,"credential_ids":["cred-1"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	caps := ExecutionCapabilities{
		FeatureEnabled: true, SingleTenant: true, AdminAuthorized: true,
		StepUpAuthorized: true, AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true,
		CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true,
	}
	receipt := EvaluateExecutionGates(d, caps)
	if receipt.Status != "blocked" || !receipt.GatesReady || receipt.ExecutionEligible || receipt.Executable || len(receipt.MissingGates) != 0 {
		t.Fatalf("ready receipt = %+v", receipt)
	}
	caps.CredentialsSupported = false
	receipt = EvaluateExecutionGates(d, caps)
	if receipt.ExecutionEligible || len(receipt.MissingGates) != 1 || receipt.MissingGates[0] != "credential_support" {
		t.Fatalf("credential gate = %+v", receipt)
	}
}

func TestBindExecutionReceiptIsDeterministicAndScoped(t *testing.T) {
	t.Parallel()
	d, _, err := Normalize(json.RawMessage(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30,"expected_exit_code":0}]}`))
	if err != nil {
		t.Fatal(err)
	}
	receipt := EvaluateExecutionGates(d, ExecutionCapabilities{})
	first := BindExecutionReceipt("acme", "cmd_1", 1, strings.Repeat("a", 64), receipt)
	second := BindExecutionReceipt("acme", "cmd_1", 1, strings.Repeat("a", 64), receipt)
	if first != second {
		t.Fatalf("binding is not deterministic: first=%+v second=%+v", first, second)
	}
	if len(first.GateDigest) != 64 || len(first.ReceiptID) != len("cmdpreflight_v1_")+64 || !strings.HasPrefix(first.ReceiptID, "cmdpreflight_v1_") {
		t.Fatalf("unexpected binding shape: %+v", first)
	}
	for _, changed := range []struct {
		name string
		got  ExecutionReceiptBinding
	}{
		{"tenant", BindExecutionReceipt("other", "cmd_1", 1, strings.Repeat("a", 64), receipt)},
		{"automation", BindExecutionReceipt("acme", "cmd_2", 1, strings.Repeat("a", 64), receipt)},
		{"version", BindExecutionReceipt("acme", "cmd_1", 2, strings.Repeat("a", 64), receipt)},
		{"definition", BindExecutionReceipt("acme", "cmd_1", 1, strings.Repeat("b", 64), receipt)},
	} {
		if changed.got == first {
			t.Fatalf("%s did not change the binding: %+v", changed.name, changed.got)
		}
	}
	if receipt.Executable || receipt.ExecutionEligible {
		t.Fatalf("binding changed execution eligibility: %+v", receipt)
	}
}
