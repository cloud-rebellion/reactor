package codegen

import (
	"context"
	"strings"
	"testing"
)

func TestSourceDAGDoesNotTrustUnrelatedMethodNames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		dag    string
	}{
		{
			name: "step",
			source: `package main
import "context"
func run(ctx context.Context) {
  fake := struct{ Step func(context.Context, string, int, func(context.Context) (int, error)) (int, error) }{}
  _, _ = fake.Step(ctx, "send", 0, func(context.Context) (int, error) { return 1, nil })
}`,
			dag: `{"steps":[{"name":"send","kind":"step"}]}`,
		},
		{
			name: "sleep",
			source: `package main
import "context"
func run(ctx context.Context) {
  fake := struct{ Sleep func(context.Context, string, int) error }{}
  _ = fake.Sleep(ctx, "pause", 1)
}`,
			dag: `{"steps":[{"name":"pause","kind":"sleep"}]}`,
		},
		{
			name: "await signal",
			source: `package main
import "context"
func run(ctx context.Context) {
  fake := struct{ AwaitSignal func(context.Context, string, int) (int, error) }{}
  _, _ = fake.AwaitSignal(ctx, "approved", 1)
}`,
			dag: `{"steps":[{"name":"approved","kind":"await_signal"}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSourceDAG(tc.source, []byte(tc.dag))
			if err == nil || !strings.Contains(err.Error(), "DAG nodes missing from source") {
				t.Fatalf("unrelated method supplied durable source evidence: %v", err)
			}
		})
	}
}

func TestSourceDAGDoesNotTrustDotImportShadow(t *testing.T) {
	source := `package main
import (
  "context"
  . "github.com/bright-interaction/reactor/sdk"
)
func run(ctx context.Context) {
  var _ Flow
  Step := func(Flow, context.Context, string, StepOpts, func(context.Context) (int, error)) (int, error) { return 0, nil }
  _, _ = Step(nil, ctx, "send", StepOpts{}, func(context.Context) (int, error) { return 1, nil })
}`
	err := ValidateSourceDAG(source, []byte(`{"steps":[{"name":"send","kind":"step"}]}`))
	if err == nil || !strings.Contains(err.Error(), "DAG nodes missing from source") {
		t.Fatalf("shadowed dot-import name supplied SDK evidence: %v", err)
	}
}

func TestSourceDAGAcceptsInferredFlowAlias(t *testing.T) {
	source := `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func run(ctx context.Context, flow reactor.Flow) error {
  alias := flow
  var next = alias
  return next.Sleep(ctx, "pause", 1)
}`
	if err := ValidateSourceDAG(source, []byte(`{"steps":[{"name":"pause","kind":"sleep"}]}`)); err != nil {
		t.Fatalf("directly inferred SDK Flow alias was rejected: %v", err)
	}
}

func TestSourceDAGRecognizesGenericDotImportedSDKStep(t *testing.T) {
	source := `package main
import (
  "context"
  . "github.com/bright-interaction/reactor/sdk"
)
func run(ctx context.Context, flow Flow) error {
  _, err := Step[int](flow, ctx, "send", StepOpts{}, func(context.Context) (int, error) { return 1, nil })
  return err
}`
	if err := ValidateSourceDAG(source, []byte(`{"steps":[{"name":"send","kind":"step"}]}`)); err != nil {
		t.Fatalf("generic dot-imported SDK Step was rejected: %v", err)
	}
}

func TestValidateWorkflowSourceRejectsUnrelatedStepMethod(t *testing.T) {
	source := `package main
import "context"
func main() {}
func run(ctx context.Context) {
  fake := struct{ Step func(context.Context, string, int, func(context.Context) (int, error)) (int, error) }{}
  _, _ = fake.Step(ctx, "send", 0, func(context.Context) (int, error) { return 1, nil })
}`
	err := ValidateWorkflowSource(context.Background(), ValidateSourceRequest{
		Slug: "fake-step", MainGo: source, DAGJSON: `{"steps":[{"name":"send","kind":"step"}]}`,
	})
	if err == nil || !strings.Contains(err.Error(), "DAG nodes missing from source") {
		t.Fatalf("validation accepted a fabricated durable step: %v", err)
	}
}
