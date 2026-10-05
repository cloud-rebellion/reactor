package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const orderedDurableCalls = `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "send", reactor.StepOpts{}, func(context.Context) (string, error) { return "sent", nil })
  if err != nil { return err }
  _, err = reactor.Step(flow, ctx, "fetch", reactor.StepOpts{}, func(context.Context) (string, error) { return "fetched", nil })
  return err
}`

func TestValidateSourceDAGRejectsImpossibleDeclaredDependencyOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		dag  string
	}{
		{"steps", `{"steps":[{"name":"send","kind":"step","depends_on":["fetch"]},{"name":"fetch","kind":"step"}]}`},
		{"nodes", `{"nodes":[{"id":"send","kind":"step"},{"id":"fetch","kind":"step"}],"edges":[{"from":"fetch","to":"send"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSourceDAG(orderedDurableCalls, []byte(tc.dag))
			if err == nil || !strings.Contains(err.Error(), `source calls "send" before "fetch"`) {
				t.Fatalf("reversed dependency accepted or unclear: %v", err)
			}
		})
	}
	valid := []byte(`{"steps":[{"name":"send","kind":"step"},{"name":"fetch","kind":"step","depends_on":["send"]}]}`)
	if err := ValidateSourceDAG(orderedDurableCalls, valid); err != nil {
		t.Fatalf("correctly ordered dependency rejected: %v", err)
	}
	// The selected-file path used by both HTTP authoring tools and retained
	// source proof must enforce the same rule as the direct validator.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(orderedDurableCalls), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceDAGFiles(root, []byte(`{"nodes":[{"id":"send","kind":"step"},{"id":"fetch","kind":"step"}],"edges":[{"from":"fetch","to":"send"}]}`), []string{"main.go"}); err == nil || !strings.Contains(err.Error(), "dependency order mismatch") {
		t.Fatalf("selected-file proof accepted reversed dependency: %v", err)
	}
	// The middle node is in another function, so there is no direct reversed
	// edge between the two source-ordered calls. The transitive path still
	// requires fetch to precede send and must be rejected.
	withMiddle := orderedDurableCalls + `
func middle(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "enrich", reactor.StepOpts{}, func(context.Context) (string, error) { return "enriched", nil })
  return err
}`
	transitive := []byte(`{"steps":[{"name":"send","kind":"step","depends_on":["enrich"]},{"name":"enrich","kind":"step","depends_on":["fetch"]},{"name":"fetch","kind":"step"}]}`)
	if err := ValidateSourceDAG(withMiddle, transitive); err == nil || !strings.Contains(err.Error(), "dependency order mismatch") {
		t.Fatalf("transitive reversed dependency accepted: %v", err)
	}
}

func TestValidateSourceDAGOrderDoesNotInferBranchOrHelperOrder(t *testing.T) {
	branchSource := `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func run(ctx context.Context, flow reactor.Flow, cond bool) error {
  if cond {
    _, err := reactor.Step(flow, ctx, "send", reactor.StepOpts{}, func(context.Context) (string, error) { return "sent", nil })
    return err
  }
  _, err := reactor.Step(flow, ctx, "fetch", reactor.StepOpts{}, func(context.Context) (string, error) { return "fetched", nil })
  return err
}`
	dag := []byte(`{"nodes":[{"id":"send","kind":"step"},{"id":"fetch","kind":"step"}],"edges":[{"from":"fetch","to":"send"}]}`)
	if err := ValidateSourceDAG(branchSource, dag); err != nil {
		t.Fatalf("branch order treated as certain: %v", err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "send", reactor.StepOpts{}, func(context.Context) (string, error) { return "sent", nil })
  return err
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "helpers.go"), []byte(`package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func helper(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "fetch", reactor.StepOpts{}, func(context.Context) (string, error) { return "fetched", nil })
  return err
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Calls in separate functions or files do not prove an execution order,
	// even though the source is listed in a stable file order.
	if err := ValidateSourceDAGFiles(root, dag, []string{"main.go", "helpers.go"}); err != nil {
		t.Fatalf("cross-file source text was treated as call order: %v", err)
	}
}
