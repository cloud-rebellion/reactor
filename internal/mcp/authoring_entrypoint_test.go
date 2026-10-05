package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestMCPAuthoringRejectsWorkflowWithoutRuntimeEntrypoint(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	const source = `package main
import (
    "context"
    reactor "github.com/bright-interaction/reactor/sdk"
)
func run(ctx context.Context, flow reactor.Flow, _ struct{}) error {
    _, err := reactor.Step(flow, ctx, "execute", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
    return err
}
func main() {}
`
	args := map[string]any{
		"slug": "missing-entrypoint", "main_go": source,
		"dag": map[string]any{"steps": []any{map[string]any{"name": "execute", "kind": "step"}}},
	}
	for _, tool := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
		result := callOperationalTool(t, s, tool, args, true)
		if !strings.Contains(string(result), "runtime.Serve") {
			t.Fatalf("%s did not identify the missing workflow entrypoint: %s", tool, result)
		}
	}
	if _, err := j.WorkflowIDBySlug(context.Background(), "missing-entrypoint"); err == nil {
		t.Fatal("workflow without runtime.Serve was registered")
	}
}

func TestMCPWorkflowEntrypointRequiresDirectImportedServe(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		wantOK bool
	}{
		{"aliased runtime", `package main
import rt "github.com/bright-interaction/reactor/sdk/runtime"
func main() { rt.Serve(workflow, trigger, run) }`, true},
		{"dot imported runtime", `package main
import . "github.com/bright-interaction/reactor/sdk/runtime"
func main() { Serve(workflow, trigger, run) }`, true},
		{"exit before Serve", `package main
import (
 "os"
 rt "github.com/bright-interaction/reactor/sdk/runtime"
)
func main() { os.Exit(0); rt.Serve(workflow, trigger, run) }`, false},
		{"extra statement after Serve", `package main
import rt "github.com/bright-interaction/reactor/sdk/runtime"
func main() { rt.Serve(workflow, trigger, run); println("untracked") }`, false},
		{"unused helper", `package main
import rt "github.com/bright-interaction/reactor/sdk/runtime"
func helper() { rt.Serve(workflow, trigger, run) }
func main() {}`, false},
		{"conditional call", `package main
import rt "github.com/bright-interaction/reactor/sdk/runtime"
func main() { if false { rt.Serve(workflow, trigger, run) } }`, false},
		{"lookalike method", `package main
func main() { runtime.Serve(workflow, trigger, run) }`, false},
		{"shadowed runtime alias", `package main
import rt "github.com/bright-interaction/reactor/sdk/runtime"
type fakeRuntime struct{}
func (fakeRuntime) Serve() {}
func main() { _ = rt.IsDryRun(); rt := fakeRuntime{}; rt.Serve() }`, false},
		{"string lookalike", `package main
func main() { println("runtime.Serve(workflow, trigger, run)") }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireMCPWorkflowEntrypoint(tc.source)
			if (err == nil) != tc.wantOK {
				t.Fatalf("entrypoint validation error = %v, want accepted=%t", err, tc.wantOK)
			}
		})
	}
}

func TestMCPWorkflowEntrypointBoundedBeforeParsing(t *testing.T) {
	oversized := strings.Repeat("x", maxMCPWorkflowAuthoringSourceBytes+1)
	if err := requireMCPWorkflowEntrypoint(oversized); err == nil || !strings.Contains(err.Error(), "main_go exceeds") {
		t.Fatalf("oversized source was parsed or accepted: %v", err)
	}
}

func TestMCPAuthoringRejectsProcessExitBeforeServe(t *testing.T) {
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	const slug = "exits-before-serve"
	source, dag := visualStepFixture(slug, "execute")
	source = []byte(strings.Replace(string(source), `"context"`, `"context"
    "os"`, 1))
	source = []byte(strings.Replace(string(source), `func main() { runtime.Serve(`,
		`func main() { os.Exit(0); runtime.Serve(`, 1))
	args := map[string]any{"slug": slug, "main_go": string(source), "dag": dag}
	for _, tool := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
		result := callOperationalTool(t, s, tool, args, true)
		if !strings.Contains(string(result), "main_go main() must contain only a direct sdk/runtime.Serve") {
			t.Fatalf("%s did not reject early process exit: %s", tool, result)
		}
	}
	if _, err := j.WorkflowIDBySlug(context.Background(), slug); err == nil {
		t.Fatal("workflow that exits before runtime.Serve was registered")
	}
}
