package codegen

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVisualSplitRejectsLiteralNilPredicateAtAuthoring(t *testing.T) {
	const dag = `{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`
	for _, call := range []string{
		`yes, no := b.Split([]int{1}, nil); return len(yes) + len(no), nil`,
		`yes, no := b.Split([]int{1}, (nil)); return len(yes) + len(no), nil`,
		`yes, no, err := b.SplitObserved(stepCtx, "route", []int{1}, nil); return len(yes) + len(no), err`,
	} {
		source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(stepCtx context.Context) (int, error) {
    ` + call + `
  })
  return err
}`
		err := ValidateSourceDAG(source, []byte(dag))
		var visualErr *VisualSourceMismatch
		if !errors.As(err, &visualErr) || !strings.Contains(err.Error(), "nil predicate") {
			t.Fatalf("literal nil split passed authoring or lost visual mismatch type: %v", err)
		}
	}
}

const sourceWithFourVisualHelpers = `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) {
    yes, no := b.Split[int]([]int{1, 2}, func(n int) bool { return n%2 == 0 })
    each := b.Iterate(yes, func(n int) int { return n * 2 })
    total := b.Aggregate(each, 0, func(sum, n int) int { return sum + n })
    return len(b.Merge(no, []int{total})), nil
  })
  return err
}
`

const fourVisualBlocksDAG = `{"nodes":[{"id":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"},{"id":"each","kind":"iterate"},{"id":"total","kind":"aggregate"},{"id":"join","kind":"merge"}],"edges":[{"from":"route","to":"each","route":"yes"},{"from":"each","to":"total"},{"from":"total","to":"join"}]}}]}`

func TestVisualFlowSourceCallsMatchEnclosingStep(t *testing.T) {
	if err := ValidateSourceDAG(sourceWithFourVisualHelpers, []byte(fourVisualBlocksDAG)); err != nil {
		t.Fatalf("direct aliased SDK helper calls rejected: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper.go"), []byte(sourceWithFourVisualHelpers), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceDAGDir(dir, []byte(fourVisualBlocksDAG)); err != nil {
		t.Fatalf("helper-file Step closure rejected: %v", err)
	}
	withoutMerge := strings.Replace(sourceWithFourVisualHelpers, "b.Merge(no, []int{total})", "no", 1)
	if err := os.WriteFile(filepath.Join(dir, "helper.go"), []byte(withoutMerge), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceDAGDir(dir, []byte(fourVisualBlocksDAG)); err == nil || !strings.Contains(err.Error(), "0 direct sdk/blocks.Merge calls") {
		t.Fatalf("directory build accepted missing helper call: %v", err)
	}
}

const sourceWithDataShapingHelpers = `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) {
    mapped := b.Map([]int{1, 2}, func(n int) int { return n * 2 })
    filtered := b.Filter(mapped, func(n int) bool { return n > 2 })
    grouped := b.GroupBy(filtered, func(n int) int { return n % 2 })
    return len(grouped), nil
  })
  return err
}`

const dataShapingDAG = `{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"map","kind":"map"},{"id":"filter","kind":"filter"},{"id":"group","kind":"group_by"}],"edges":[{"from":"map","to":"filter"},{"from":"filter","to":"group"}]}}]}`

func TestVisualFlowBuiltInKindsRejectPhantomBlocks(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) { return 1, nil })
  return err
}`
	for _, kind := range []string{
		"if", "switch", "split", "iterate", "aggregate", "merge", "map", "filter",
		"reduce", "group_by", "sort", "limit", "chunk", "flatten", "zip", "join",
		"unique", "coalesce",
	} {
		t.Run(kind, func(t *testing.T) {
			dag := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"block","kind":"` + kind + `"}]}}]}`)
			if err := ValidateSourceDAG(source, dag); err == nil || !strings.Contains(err.Error(), "visual_flow mismatch") {
				t.Fatalf("phantom %s block accepted: %v", kind, err)
			}
		})
	}
}

func TestVisualFlowDataShapingNeedsDirectSourceEvidence(t *testing.T) {
	if err := ValidateSourceDAG(sourceWithDataShapingHelpers, []byte(dataShapingDAG)); err != nil {
		t.Fatalf("matching data-shaping helpers rejected: %v", err)
	}
	withoutFilter := strings.Replace(sourceWithDataShapingHelpers, "filtered := b.Filter(mapped, func(n int) bool { return n > 2 })", "filtered := mapped", 1)
	if err := ValidateSourceDAG(withoutFilter, []byte(dataShapingDAG)); err == nil || !strings.Contains(err.Error(), "declares 1 filter blocks") {
		t.Fatalf("phantom visual filter accepted: %v", err)
	}
	withoutFilterBlock := strings.Replace(dataShapingDAG, `,{"id":"filter","kind":"filter"}`, "", 1)
	withoutFilterBlock = strings.Replace(withoutFilterBlock, `"edges":[{"from":"map","to":"filter"},{"from":"filter","to":"group"}]`, `"edges":[{"from":"map","to":"group"}]`, 1)
	if err := ValidateSourceDAG(sourceWithDataShapingHelpers, []byte(withoutFilterBlock)); err == nil || !strings.Contains(err.Error(), "declares 0 filter blocks") {
		t.Fatalf("unrepresented filter helper accepted: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(sourceWithDataShapingHelpers), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceDAGDir(dir, []byte(dataShapingDAG)); err != nil {
		t.Fatalf("matching directory data-shaping helpers rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(withoutFilter), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceDAGDir(dir, []byte(dataShapingDAG)); err == nil || !strings.Contains(err.Error(), "declares 1 filter blocks") {
		t.Fatalf("directory build accepted phantom filter: %v", err)
	}
}

func TestVisualFlowZipAndJoinUseDistinctDirectCalls(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) {
    zipped := b.Zip([]int{1}, []int{2}, func(a, b int) int { return a + b })
    joined, joinErr := b.JoinByKey([]int{1}, []int{2}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)
    if joinErr != nil { return 0, joinErr }
    return len(zipped) + len(joined), nil
  })
  return err
}`
	dag := `{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"zip","kind":"zip"},{"id":"join","kind":"join"}],"edges":[{"from":"zip","to":"join"}]}}]}`
	if err := ValidateSourceDAG(source, []byte(dag)); err != nil {
		t.Fatalf("direct Zip and JoinByKey visual calls rejected: %v", err)
	}
	withoutZip := strings.Replace(source, "zipped := b.Zip([]int{1}, []int{2}, func(a, b int) int { return a + b })", "zipped := []int{1}", 1)
	if err := ValidateSourceDAG(withoutZip, []byte(dag)); err == nil {
		t.Fatal("visual zip borrowed JoinByKey evidence")
	}
	withoutJoin := strings.Replace(source, "joined, joinErr := b.JoinByKey([]int{1}, []int{2}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)", "joined, joinErr := []int{1}, error(nil)", 1)
	if err := ValidateSourceDAG(withoutJoin, []byte(dag)); err == nil {
		t.Fatal("visual join borrowed Zip evidence")
	}
	typedMergeDAG := strings.Replace(dag, `{"id":"zip","kind":"zip"}`, `{"id":"merge","kind":"merge","mode":"position_truncate"},{"id":"zip","kind":"zip"}`, 1)
	typedMergeSource := strings.Replace(source, "zipped := b.Zip(", "merged := b.Zip([]int{1}, []int{2}, func(a, b int) int { return a + b })\n    _ = merged\n    zipped := b.Zip(", 1)
	if err := ValidateSourceDAG(typedMergeSource, []byte(typedMergeDAG)); err != nil {
		t.Fatalf("typed positional merge and separate visual zip rejected: %v", err)
	}
	if err := ValidateSourceDAG(source, []byte(typedMergeDAG)); err == nil {
		t.Fatal("one Zip call satisfied typed merge and visual zip")
	}
	typedJoinDAG := strings.Replace(dag, `{"id":"join","kind":"join"}`, `{"id":"join","kind":"join"},{"id":"merge","kind":"merge","mode":"full_join","max_rows":10}`, 1)
	typedJoinSource := strings.Replace(source, "joined, joinErr := b.JoinByKey(", "merged, mergeErr := b.JoinByKey([]int{1}, []int{2}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)\n    if mergeErr != nil { return 0, mergeErr }\n    _ = merged\n    joined, joinErr := b.JoinByKey(", 1)
	if err := ValidateSourceDAG(typedJoinSource, []byte(typedJoinDAG)); err != nil {
		t.Fatalf("typed key merge and separate visual join rejected: %v", err)
	}
	if err := ValidateSourceDAG(source, []byte(typedJoinDAG)); err == nil {
		t.Fatal("one JoinByKey call satisfied typed merge and visual join")
	}
}

func TestVisualFlowSourceRecognizesExplicitMergeModeHelpers(t *testing.T) {
	for name, replacement := range map[string]string{
		"JoinByKey": `joined, joinErr := b.JoinByKey(no, []int{total}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 100)
    if joinErr != nil { return 0, joinErr }
    return len(joined), nil`,
		"CrossJoin": `joined, joinErr := b.CrossJoin(no, []int{total}, 100)
    if joinErr != nil { return 0, joinErr }
    return len(joined), nil`,
		"ZipAll": `joined, joinErr := b.ZipAll(no, []int{total}, 100)
    if joinErr != nil { return 0, joinErr }
    return len(joined), nil`,
	} {
		t.Run(name, func(t *testing.T) {
			source := strings.Replace(sourceWithFourVisualHelpers, "return len(b.Merge(no, []int{total})), nil", replacement, 1)
			if err := ValidateSourceDAG(source, []byte(fourVisualBlocksDAG)); err != nil {
				t.Fatalf("explicit merge helper rejected: %v", err)
			}
		})
	}
}

func TestVisualFlowTypedMergeModeMustMatchDirectSource(t *testing.T) {
	joinSource := strings.Replace(sourceWithFourVisualHelpers,
		"return len(b.Merge(no, []int{total})), nil",
		`joined, joinErr := b.JoinByKey(no, []int{total}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 100)
    if joinErr != nil { return 0, joinErr }
    return len(joined), nil`, 1)
	baseDAG := strings.Replace(fourVisualBlocksDAG, `{"id":"join","kind":"merge"}`,
		`{"id":"join","kind":"merge","mode":"full_join","key":"customer_id","max_rows":100}`, 1)
	if err := ValidateSourceDAG(joinSource, []byte(baseDAG)); err != nil {
		t.Fatalf("matching typed merge rejected: %v", err)
	}
	for _, tc := range []struct{ name, source, dag string }{
		{"wrong mode", joinSource, strings.Replace(baseDAG, `"mode":"full_join"`, `"mode":"left_join"`, 1)},
		{"wrong bound", joinSource, strings.Replace(baseDAG, `"max_rows":100`, `"max_rows":101`, 1)},
		{"wrong helper", sourceWithFourVisualHelpers, baseDAG},
		{"dynamic bound", strings.Replace(joinSource, "b.JoinFull, 100)", "b.JoinFull, limit)", 1), baseDAG},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSourceDAG(tc.source, []byte(tc.dag)); err == nil || !strings.Contains(err.Error(), "direct matching helper calls") {
				t.Fatalf("typed merge mismatch accepted: %v", err)
			}
		})
	}
}

func TestVisualFlowSourceCallsRejectMissingAndUndeclaredKinds(t *testing.T) {
	withoutMerge := strings.Replace(sourceWithFourVisualHelpers, "b.Merge(no, []int{total})", "no", 1)
	if err := ValidateSourceDAG(withoutMerge, []byte(fourVisualBlocksDAG)); err == nil || !strings.Contains(err.Error(), "declares 1 merge blocks") || !strings.Contains(err.Error(), "0 direct sdk/blocks.Merge calls") {
		t.Fatalf("missing merge source evidence was accepted: %v", err)
	}
	customOnly := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"logic","kind":"custom"}]}}]}`)
	if err := ValidateSourceDAG(sourceWithFourVisualHelpers, customOnly); err == nil || !strings.Contains(err.Error(), "declares 0 aggregate blocks") {
		t.Fatalf("unrepresented direct SDK calls were accepted: %v", err)
	}
	twoSplits := []byte(strings.Replace(fourVisualBlocksDAG, `{"id":"route","kind":"split"}`, `{"id":"route","kind":"split"},{"id":"again","kind":"split"}`, 1))
	if err := ValidateSourceDAG(sourceWithFourVisualHelpers, twoSplits); err == nil || !strings.Contains(err.Error(), "declares 2 split blocks") {
		t.Fatalf("duplicate visual split without second call was accepted: %v", err)
	}
}

func TestVisualFlowSourceCallsDoNotBorrowOtherStepOrHelper(t *testing.T) {
	otherStep := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) { return 1, nil })
  if err != nil { return err }
  _, err = r.Step(flow, ctx, "other", r.StepOpts{}, func(context.Context) (int, error) {
    yes, _ := b.Split([]int{1}, func(n int) bool { return true })
    return len(yes), nil
  })
  return err
}`
	dag := []byte(`{"nodes":[{"id":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}},{"id":"other","kind":"step"}]}`)
	if err := ValidateSourceDAG(otherStep, dag); err == nil || !strings.Contains(err.Error(), `step "process" declares 1 split blocks`) {
		t.Fatalf("call from another step was accepted: %v", err)
	}

	separateHelper := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func route() int {
  yes, _ := b.Split([]int{1}, func(n int) bool { return true })
  return len(yes)
}
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) { return route(), nil })
  return err
}`
	if err := ValidateSourceDAG(separateHelper, []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`)); err == nil || !strings.Contains(err.Error(), "0 direct sdk/blocks.Split calls") {
		t.Fatalf("call in a separate helper was accepted as direct Step evidence: %v", err)
	}
}

func TestVisualFlowSourceCallsRejectShadowedAliasAndNestedClosure(t *testing.T) {
	shadowed := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
var _ = b.Split[int]
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) {
    b := struct{ Split func([]int, func(int) bool) ([]int, []int) }{}
    yes, _ := b.Split([]int{1}, func(n int) bool { return true })
    return len(yes), nil
  })
  return err
}`
	dag := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`)
	if err := ValidateSourceDAG(shadowed, dag); err == nil || !strings.Contains(err.Error(), "0 direct sdk/blocks.Split calls") {
		t.Fatalf("shadowed blocks alias was accepted as SDK call: %v", err)
	}

	nested := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) {
    unused := func() { _, _ = b.Split([]int{1}, func(n int) bool { return true }) }
    _ = unused
    return 1, nil
  })
  return err
}`
	if err := ValidateSourceDAG(nested, dag); err == nil || !strings.Contains(err.Error(), "0 direct sdk/blocks.Split calls") {
		t.Fatalf("uninvoked nested closure was accepted as direct Step call: %v", err)
	}
}

func TestVisualFlowSourceCallsAcceptDotImportWithoutLocalShadow(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  . "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "process", r.StepOpts{}, func(context.Context) (int, error) {
    yes, _ := Split([]int{1}, func(n int) bool { return true })
    return len(yes), nil
  })
  return err
}`
	dag := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`)
	if err := ValidateSourceDAG(source, dag); err != nil {
		t.Fatalf("dot-imported direct helper call rejected: %v", err)
	}
}

func TestVisualFlowSourceCallsAcceptFlowMethodAndDefaultBlocksImport(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := flow.Step(ctx, "process", r.StepOpts{}, func(context.Context) (any, error) {
    yes, _ := blocks.Split([]int{1}, func(n int) bool { return true })
    return yes, nil
  })
  return err
}`
	dag := []byte(`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`)
	if err := ValidateSourceDAG(source, dag); err != nil {
		t.Fatalf("Flow.Step with default blocks import rejected: %v", err)
	}
}

func TestObservedJoinRequiresMatchingDeclaredStepBlock(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "merge-step", r.StepOpts{}, func(stepCtx context.Context) (int, error) {
    joined, joinErr := b.JoinByKeyObserved(stepCtx, "join", []int{1}, []int{1}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)
    return len(joined), joinErr
  })
  return err
}`
	dag := `{"nodes":[{"id":"merge-step","kind":"step","visual_flow":{"blocks":[{"id":"join","kind":"merge","mode":"full_join","key":"customer_id","max_rows":10}]}}]}`
	if err := ValidateSourceDAG(source, []byte(dag)); err != nil {
		t.Fatalf("matching observed merge rejected: %v", err)
	}
	for _, tc := range []struct{ name, source, dag string }{
		{"wrong block id", strings.Replace(source, `"join"`, `"other"`, 1), dag},
		{"dynamic block id", strings.Replace(source, `"join"`, `blockID`, 1), dag},
		{"wrong bound", strings.Replace(source, "b.JoinFull, 10)", "b.JoinFull, 11)", 1), dag},
		{"wrong mode", strings.Replace(source, "b.JoinFull, 10)", "b.JoinLeft, 10)", 1), dag},
		{"undeclared block", source, `{"nodes":[{"id":"merge-step","kind":"step"}]}`},
		{"undeclared step", strings.Replace(source, `"merge-step"`, `"other-step"`, 1), dag},
		{"outside direct Step", strings.Replace(source,
			`    joined, joinErr := b.JoinByKeyObserved(stepCtx, "join", []int{1}, []int{1}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)
    return len(joined), joinErr`, `    return 0, nil`, 1) + `
func external(ctx context.Context) {
  _, _ = b.JoinByKeyObserved(ctx, "join", []int{1}, []int{1}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)
}`, dag},
		{"duplicate observed call", strings.Replace(source, "    return len(joined), joinErr", `    _, _ = b.JoinByKeyObserved(stepCtx, "join", []int{1}, []int{1}, func(n int) int { return n }, func(n int) int { return n }, b.JoinFull, 10)
    return len(joined), joinErr`, 1), dag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSourceDAG(tc.source, []byte(tc.dag)); err == nil {
				t.Fatal("unsafe observed merge declaration was accepted")
			}
		})
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceDAGDir(dir, []byte(dag)); err != nil {
		t.Fatalf("directory validation rejected matching observed merge: %v", err)
	}
	if err := ValidateSourceDAGDir(dir, []byte(`{"nodes":[{"id":"merge-step","kind":"step"}]}`)); err == nil {
		t.Fatal("directory validation accepted observed merge without visual_flow")
	}
}

func TestObservedSplitRequiresLiteralDeclaredBlockInStepClosure(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "route-step", r.StepOpts{}, func(stepCtx context.Context) (int, error) {
    yes, _, splitErr := b.SplitObserved(stepCtx, "route", []int{1}, func(n int) bool { return n > 0 })
    return len(yes), splitErr
  })
  return err
}`
	dag := `{"nodes":[{"id":"route-step","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`
	if err := ValidateSourceDAG(source, []byte(dag)); err != nil {
		t.Fatalf("matching observed split rejected: %v", err)
	}
	for _, tc := range []struct{ name, source, dag string }{
		{"wrong block id", strings.Replace(source, `"route"`, `"other"`, 1), dag},
		{"dynamic block id", strings.Replace(source, `"route"`, `blockID`, 1), dag},
		{"wrong declaration kind", source, strings.Replace(dag, `"split"`, `"iterate"`, 1)},
		{"undeclared block", source, `{"nodes":[{"id":"route-step","kind":"step"}]}`},
		{"outside direct Step", strings.Replace(source,
			`    yes, _, splitErr := b.SplitObserved(stepCtx, "route", []int{1}, func(n int) bool { return n > 0 })
    return len(yes), splitErr`, `    return 0, nil`, 1) + `
func external(ctx context.Context) {
  _, _, _ = b.SplitObserved(ctx, "route", []int{1}, func(n int) bool { return n > 0 })
}`, dag},
		{"duplicate observed call", strings.Replace(source, "    return len(yes), splitErr", `    _, _, _ = b.SplitObserved(stepCtx, "route", []int{1}, func(n int) bool { return n > 0 })
    return len(yes), splitErr`, 1), dag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSourceDAG(tc.source, []byte(tc.dag)); err == nil {
				t.Fatal("unsafe observed split declaration was accepted")
			}
		})
	}
}

func TestObservedCollectionsRequireLiteralDeclaredBlockInStepClosure(t *testing.T) {
	source := `package main
import (
  "context"
  r "github.com/bright-interaction/reactor/sdk"
  b "github.com/bright-interaction/reactor/sdk/blocks"
)
func Run(ctx context.Context, flow r.Flow) error {
  _, err := r.Step(flow, ctx, "collection-step", r.StepOpts{}, func(stepCtx context.Context) (int, error) {
    mapped, mapErr := b.IterateObserved(stepCtx, "each", []int{1, 2}, func(n int) int { return n * 2 })
    if mapErr != nil { return 0, mapErr }
    sum, foldErr := b.AggregateObserved(stepCtx, "sum", mapped, 0, func(acc, n int) int { return acc + n })
    return sum, foldErr
  })
  return err
}`
	dag := `{"nodes":[{"id":"collection-step","kind":"step","visual_flow":{"blocks":[{"id":"each","kind":"iterate"},{"id":"sum","kind":"aggregate"}],"edges":[{"from":"each","to":"sum"}]}}]}`
	if err := ValidateSourceDAG(source, []byte(dag)); err != nil {
		t.Fatalf("matching observed collection helpers rejected: %v", err)
	}
	for _, tc := range []struct{ name, source, dag string }{
		{"wrong iterate id", strings.Replace(source, `"each"`, `"other"`, 1), dag},
		{"wrong aggregate id", strings.Replace(source, `"sum"`, `"other"`, 1), dag},
		{"dynamic iterate id", strings.Replace(source, `"each"`, `blockID`, 1), dag},
		{"dynamic aggregate id", strings.Replace(source, `"sum"`, `blockID`, 1), dag},
		{"wrong declaration kind", source, strings.Replace(dag, `"aggregate"`, `"iterate"`, 1)},
		{"undeclared collection blocks", source, `{"nodes":[{"id":"collection-step","kind":"step"}]}`},
		{"outside direct Step", strings.Replace(source,
			`    mapped, mapErr := b.IterateObserved(stepCtx, "each", []int{1, 2}, func(n int) int { return n * 2 })`,
			`    mapped, mapErr := []int{1, 2}, error(nil)`, 1) + `
func external(ctx context.Context) {
  _, _ = b.IterateObserved(ctx, "each", []int{1}, func(n int) int { return n })
}`, dag},
		{"duplicate aggregate call", strings.Replace(source,
			`    return sum, foldErr`,
			`    _, _ = b.AggregateObserved(stepCtx, "sum", mapped, 0, func(acc, n int) int { return acc + n })
    return sum, foldErr`, 1), dag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSourceDAG(tc.source, []byte(tc.dag)); err == nil {
				t.Fatal("unsafe observed collection declaration accepted")
			}
		})
	}
}
