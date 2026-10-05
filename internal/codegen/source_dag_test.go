package codegen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceDAGDiagnosticsDoNotExposeStateRoot(t *testing.T) {
	root := t.TempDir()
	assertPathFree := func(err error, relative string) {
		t.Helper()
		if err == nil || strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), relative) {
			t.Fatalf("source/DAG diagnostic leaked root or lost relative file %q: %v", relative, err)
		}
	}

	err := ValidateSourceDAGFiles(root, []byte(`{}`), []string{"nested/helper.go"})
	assertPathFree(err, "nested/helper.go")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing selected source lost its cause: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc run("), 0o600); err != nil {
		t.Fatal(err)
	}
	assertPathFree(ValidateSourceDAGFiles(root, []byte(`{}`), []string{"main.go"}), "main.go")
	assertPathFree(ValidateSourceDAGDir(root, []byte(`{}`)), "main.go")

	missingRoot := filepath.Join(root, "missing-private-source")
	if err := ValidateSourceDAGDir(missingRoot, []byte(`{}`)); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("legacy source walk leaked root: %v", err)
	}
	if _, err := SelectedExecutableGoFiles(context.Background(), "go", missingRoot); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("compiled source selection leaked root: %v", err)
	}
	if err := validateSelectedGoFiles([]string{filepath.Join(root, "main.go")}); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("invalid selected source leaked root: %v", err)
	}
}

func TestVisualMismatchTypeDoesNotHideDurableNodeMismatch(t *testing.T) {
	source := `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "execute", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}`
	visualOnly := []byte(`{"steps":[{"name":"execute","kind":"step","visual_flow":{"blocks":[{"id":"predicate","kind":"filter"}]}}]}`)
	var visualErr *VisualSourceMismatch
	if err := ValidateSourceDAG(source, visualOnly); !errors.As(err, &visualErr) {
		t.Fatalf("visual-only annotation mismatch has type %T, want VisualSourceMismatch: %v", err, err)
	}
	wrongNode := []byte(`{"steps":[{"name":"different","kind":"step","visual_flow":{"blocks":[{"id":"predicate","kind":"filter"}]}}]}`)
	visualErr = nil
	if err := ValidateSourceDAG(source, wrongNode); err == nil || errors.As(err, &visualErr) {
		t.Fatalf("durable-node mismatch was classified as visual-only: %v", err)
	}
}

func TestValidateSourceDAGMatchesDurableCalls(t *testing.T) {
	source := `package main
import (
  "context"
  "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.SideEffect(flow, ctx, "capture", func() string { return "x" })
  if err != nil { return err }
  if err := flow.Sleep(ctx, "pause", 1); err != nil { return err }
  _, err = reactor.Step(flow, ctx, "send", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`
	dag := []byte(`{"nodes":[{"id":"capture","kind":"side_effect"},{"id":"pause","kind":"sleep"},{"id":"send","kind":"step"}]}`)
	if err := ValidateSourceDAG(source, dag); err != nil {
		t.Fatalf("matching source/DAG rejected: %v", err)
	}
}

func TestValidateSourceDAGResolvesAliasedSDKPackage(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.SideEffect(flow, ctx, "capture", func() string { return "x" })
  if err != nil { return err }
  _, err = r.Step(flow, ctx, "send", r.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`
	dag := []byte(`{"steps":[{"name":"capture","kind":"side_effect"},{"name":"send","kind":"step"}]}`)
	if err := ValidateSourceDAG(source, dag); err != nil {
		t.Fatalf("aliased SDK package rejected: %v", err)
	}
}

func TestValidateSourceDAGResolvesDotImportedSDKPackage(t *testing.T) {
	source := `package main
import (
  "context"
  . "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow Flow) error {
  _, err := Step(flow, ctx, "send", StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`
	err := ValidateSourceDAG(source, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "provide a visual DAG") || !strings.Contains(err.Error(), "send") {
		t.Fatalf("dot-imported SDK durable node was not discovered: %v", err)
	}
}

func TestValidateSourceDAGRejectsMismatchAndDynamicNames(t *testing.T) {
	source := `package main
import (
  "context"
  "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow, name string) error {
  _, err := reactor.Step(flow, ctx, name, reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`
	err := ValidateSourceDAG(source, []byte(`{"steps":[{"name":"other","kind":"step"}]}`))
	if err == nil || !strings.Contains(err.Error(), "string literal") {
		t.Fatalf("dynamic node name error = %v", err)
	}

	static := strings.Replace(source, "name,", `"send",`, 1)
	err = ValidateSourceDAG(static, []byte(`{"steps":[{"name":"other","kind":"step"}]}`))
	if err == nil || !strings.Contains(err.Error(), "source/DAG mismatch") {
		t.Fatalf("mismatch error = %v", err)
	}
}

func TestValidateSourceDAGAllowsEmptyLegacyGraph(t *testing.T) {
	if err := ValidateSourceDAG("package main\nfunc main() {}\n", []byte(`{}`)); err != nil {
		t.Fatalf("empty legacy graph rejected: %v", err)
	}
}

func TestValidateSourceDAGRequiresGraphForDurableCalls(t *testing.T) {
	source := `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "send", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`
	err := ValidateSourceDAG(source, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "provide a visual DAG") || !strings.Contains(err.Error(), "send") {
		t.Fatalf("empty DAG durable-node error = %v", err)
	}
}

func TestValidateSourceDAGDoesNotClassifyImportedSleepAsDurable(t *testing.T) {
	source := `package main
import "time"
func helper() { time.Sleep(time.Second) }
`
	if err := ValidateSourceDAG(source, []byte(`{}`)); err != nil {
		t.Fatalf("ordinary time.Sleep was classified as a durable node: %v", err)
	}
}

func TestValidateSourceDAGDoesNotClassifyShadowedSDKImportAsDurable(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
)
var _ = r.Step[int]
func helper(ctx context.Context) {
  r := struct{ Step func(context.Context, string, int, func(context.Context) (int, error)) (int, error) }{}
  _, _ = r.Step(ctx, "ordinary-function-field", 0, func(context.Context) (int, error) { return 1, nil })
}`
	if err := ValidateSourceDAG(source, []byte(`{}`)); err != nil {
		t.Fatalf("shadowed SDK import was classified as a durable call: %v", err)
	}
}

func TestValidateSourceDAGDirIncludesHelperFiles(t *testing.T) {
	dir := t.TempDir()
	main := `package main
func main() {}
`
	helper := `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func runHelper(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "helper-step", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper.go"), []byte(helper), 0o600); err != nil {
		t.Fatal(err)
	}
	dag := []byte(`{"steps":[{"name":"helper-step","kind":"step"}]}`)
	if err := ValidateSourceDAGDir(dir, dag); err != nil {
		t.Fatalf("helper node rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper.go"), []byte(strings.Replace(helper, `"helper-step"`, `"other-step"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceDAGDir(dir, dag); err == nil || !strings.Contains(err.Error(), "source/DAG mismatch") {
		t.Fatalf("helper mismatch error = %v", err)
	}
}

func TestValidateSourceDAGDirRequiresGraphForHelperCalls(t *testing.T) {
	dir := t.TempDir()
	main := `package main
func main() {}
`
	helper := `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
)
func runHelper(ctx context.Context, flow reactor.Flow) error {
  _, err := reactor.Step(flow, ctx, "helper-step", reactor.StepOpts{}, func(context.Context) (string, error) { return "ok", nil })
  return err
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper.go"), []byte(helper), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ValidateSourceDAGDir(dir, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "provide a visual DAG") || !strings.Contains(err.Error(), "helper-step") {
		t.Fatalf("empty DAG helper-node error = %v", err)
	}
}
