package codegen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/bright-interaction/reactor/internal/flowblocks"
	sdkblocks "github.com/bright-interaction/reactor/sdk/blocks"
)

const reactorSDKImportPath = "github.com/bright-interaction/reactor/sdk"
const reactorBlocksImportPath = "github.com/bright-interaction/reactor/sdk/blocks"

// These visual kinds have direct SDK helper evidence. Multiple merge helpers
// share the visual merge kind, but the declared mode and data behavior remain
// author-declared until the runtime records block-level receipts.
var directVisualHelpers = map[string]string{
	"If":                "if",
	"Switch":            "switch",
	"SwitchValue":       "switch",
	"Split":             "split",
	"SplitObserved":     "split",
	"Iterate":           "iterate",
	"IterateObserved":   "iterate",
	"Aggregate":         "aggregate",
	"AggregateObserved": "aggregate",
	"Map":               "map",
	"Filter":            "filter",
	"Reduce":            "reduce",
	"GroupBy":           "group_by",
	"SortBy":            "sort",
	"Limit":             "limit",
	"Chunk":             "chunk",
	"Flatten":           "flatten",
	"Unique":            "unique",
	"UniqueBy":          "unique",
	"Coalesce":          "coalesce",
	"Merge":             "merge",
	"Append":            "merge",
	"MergeByKey":        "merge",
	"JoinByKey":         "merge",
	"JoinByKeyObserved": "merge",
	"CrossJoin":         "merge",
	"Zip":               "merge",
	"ZipAll":            "merge",
	"MergeMaps":         "merge",
}

// All built-in kinds have a direct SDK helper. A custom block remains an
// explicitly author-declared description of arbitrary Go logic.
var checkedVisualKinds = []string{
	"aggregate", "iterate", "merge", "split", "if", "switch", "map", "filter",
	"reduce", "group_by", "sort", "limit", "chunk", "flatten", "unique", "coalesce",
}

// ValidateSourceDAG checks the executable node names discovered in a workflow
// source file against the nodes declared by its visual DAG. The MCP authoring
// path uses this to require source evidence for the declared graph. Static
// evidence shows a direct call exists, not that a branch executes at runtime.
//
// Only literal node names are representable in a static flow. A dynamic name
// is rejected when a DAG is supplied instead of silently producing a visual
// graph that cannot predict runtime behavior.
func ValidateSourceDAG(source string, dag []byte) error {
	if strings.TrimSpace(string(dag)) == "" || strings.TrimSpace(string(dag)) == "{}" {
		discovered, err := discoverSourceNodes(source)
		if err != nil {
			return err
		}
		if err := requireVisualDAG(discovered); err != nil {
			return err
		}
		calls, err := discoverDirectVisualCalls(source)
		if err != nil {
			return err
		}
		return validateDirectVisualCalls(nil, calls)
	}

	nodes, err := declaredDAGNodes(dag)
	if err != nil {
		return err
	}
	flows, err := declaredStepFlows(dag)
	if err != nil {
		return err
	}
	discovered, err := discoverSourceNodes(source)
	if err != nil {
		return err
	}
	if err := validateSourceDAGNodes(nodes, discovered); err != nil {
		return err
	}
	order, err := definiteSourceCallOrder(source)
	if err != nil {
		return err
	}
	if err := validateSourceDAGOrder(dag, order); err != nil {
		return err
	}
	calls, err := discoverDirectVisualCalls(source)
	if err != nil {
		return err
	}
	return validateDirectVisualCalls(flows, calls)
}

// ValidateSourceDAGDir is the legacy recursive source/DAG check for older
// artifacts without a pinned compiled-file selection. New authoring uses
// SelectedExecutableGoFiles and ValidateSourceDAGFiles instead.
func ValidateSourceDAGDir(dir string, dag []byte) error {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("source/DAG: cannot inspect retained workflow source")
		}
		if entry.IsDir() {
			if entry.Name() == "vendor" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("source/DAG: cannot resolve selected source path")
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return err
	}
	return validateSourceDAGFiles(dir, dag, files)
}

// SelectedExecutableGoFiles asks the same hermetic Go toolchain that publishes
// the executable which workflow-module files enter `go build .`. Imported
// local helper packages count, while unused nested packages, OS-specific and
// build-tag-excluded files cannot provide evidence for absent binary nodes.
// Call this only after module preparation and the import allowlist.
func SelectedExecutableGoFiles(ctx context.Context, gobin, dir string) ([]string, error) {
	if gobin == "" {
		gobin = "go"
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("source/DAG: cannot resolve workflow source root")
	}
	// macOS often hands MkdirTemp a /var path while the Go toolchain reports
	// its canonical /private/var target. Compare resolved directories.
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("source/DAG: cannot inspect workflow source root")
	}
	cmd := exec.CommandContext(ctx, gobin, "list", "-deps", "-json", ".")
	cmd.Dir = dir
	cmd.Env = SecureBuildEnv()
	raw, err := cmd.CombinedOutput()
	if err != nil {
		// go list diagnostics may include absolute source paths or the local
		// module cache. Keep those out of proof errors that can reach MCP and
		// dashboard readers. An author can run go list against the same staged
		// source locally for the full toolchain diagnostic.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("source/DAG: list compiled workflow packages: %w", ctx.Err())
		}
		return nil, fmt.Errorf("source/DAG: list compiled workflow packages failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	selected := []string{}
	rootFound := false
	for decoder.More() {
		var pkg struct {
			Dir      string   `json:"Dir"`
			Name     string   `json:"Name"`
			GoFiles  []string `json:"GoFiles"`
			CgoFiles []string `json:"CgoFiles"`
		}
		if err := decoder.Decode(&pkg); err != nil {
			return nil, fmt.Errorf("source/DAG: decode compiled workflow packages: %w", err)
		}
		if pkg.Dir == "" {
			continue
		}
		pkgDir, err := filepath.EvalSymlinks(pkg.Dir)
		if err != nil {
			return nil, fmt.Errorf("source/DAG: cannot resolve Go package directory")
		}
		rel, err := filepath.Rel(root, pkgDir)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue // stdlib and the separately rooted Reactor SDK
		}
		if rel == "." {
			rootFound = true
			if pkg.Name != "main" {
				return nil, fmt.Errorf("source/DAG: compiled root package must be package main")
			}
		}
		if len(pkg.CgoFiles) != 0 {
			return nil, fmt.Errorf("source/DAG: cgo is not allowed in workflow packages")
		}
		for _, name := range pkg.GoFiles {
			if name != filepath.Base(name) || name == "." {
				return nil, fmt.Errorf("source/DAG: invalid Go package file")
			}
			selected = append(selected, filepath.ToSlash(filepath.Join(rel, name)))
		}
	}
	if !rootFound || len(selected) == 0 {
		return nil, fmt.Errorf("source/DAG: compiled root package is missing")
	}
	sort.Strings(selected)
	if err := validateSelectedGoFiles(selected); err != nil {
		return nil, err
	}
	// MCP and CLI workflow builds supply main.go. If a build constraint drops
	// that file, the selected root package is not the source they reviewed.
	// The older generator validates workflow.go before it materialises main.go.
	if info, statErr := os.Lstat(filepath.Join(dir, "main.go")); statErr == nil {
		if !info.Mode().IsRegular() || !slices.Contains(selected, "main.go") {
			return nil, fmt.Errorf("source/DAG: main.go is not selected for the compiled executable")
		}
	} else if !os.IsNotExist(statErr) {
		return nil, sourceDAGFileAccessError("inspect", "main.go", statErr)
	}
	return selected, nil
}

// ValidateSourceDAGFiles checks only a pinned list of files selected for the
// executable dependency graph. The list is persisted in the immutable source
// manifest so review on another host never reinterprets build constraints.
func ValidateSourceDAGFiles(dir string, dag []byte, files []string) error {
	if err := validateSelectedGoFiles(files); err != nil {
		return err
	}
	return validateSourceDAGFiles(dir, dag, files)
}

func validateSelectedGoFiles(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("source/DAG: no compiled workflow Go files were selected")
	}
	seen := make(map[string]bool, len(files))
	for _, name := range files {
		base := path.Base(name)
		if name == "" || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") || !strings.HasSuffix(base, ".go") || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") || strings.HasSuffix(base, "_test.go") || seen[name] {
			return fmt.Errorf("source/DAG: invalid compiled workflow Go file")
		}
		seen[name] = true
	}
	return nil
}

// sourceDAGFileAccessError keeps a selected file's relative name useful to an
// author without forwarding os.PathError, which contains the local state-root
// path and can reach workflow proof/readiness responses.
func sourceDAGFileAccessError(action, name string, err error) error {
	switch {
	case os.IsNotExist(err):
		return fmt.Errorf("source/DAG: %s selected source %q: %w", action, name, os.ErrNotExist)
	case os.IsPermission(err):
		return fmt.Errorf("source/DAG: %s selected source %q: %w", action, name, os.ErrPermission)
	default:
		return fmt.Errorf("source/DAG: %s selected source %q: I/O unavailable", action, name)
	}
}

func validateSourceDAGFiles(dir string, dag []byte, files []string) error {
	emptyDAG := strings.TrimSpace(string(dag)) == "" || strings.TrimSpace(string(dag)) == "{}"
	nodes := map[string]string{}
	var err error
	if !emptyDAG {
		nodes, err = declaredDAGNodes(dag)
		if err != nil {
			return err
		}
	}
	var flows []flowblocks.StepFlow
	if !emptyDAG {
		flows, err = declaredStepFlows(dag)
		if err != nil {
			return err
		}
	}
	discovered := make(map[string]string)
	directCalls := make(map[string]map[string]int)
	var sourceOrder [][2]string
	for _, name := range files {
		filePath := filepath.Join(dir, filepath.FromSlash(name))
		info, err := os.Lstat(filePath)
		if err != nil {
			return sourceDAGFileAccessError("inspect", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("source/DAG: selected source %q is not a regular file", name)
		}
		source, err := os.ReadFile(filePath)
		if err != nil {
			return sourceDAGFileAccessError("read", name, err)
		}
		found, err := discoverSourceNodes(string(source))
		if err != nil {
			return fmt.Errorf("source/DAG: selected source %q: %w", name, err)
		}
		for node, kind := range found {
			if previous, exists := discovered[node]; exists {
				return fmt.Errorf("source/DAG: node %q is declared by both %s and %s", node, previous, kind)
			}
			discovered[node] = kind
		}
		order, err := definiteSourceCallOrder(string(source))
		if err != nil {
			return fmt.Errorf("source/DAG: selected source %q: %w", name, err)
		}
		if len(sourceOrder)+len(order) > maxDefiniteSourceOrderPairs {
			return fmt.Errorf("source/DAG: durable call order exceeds bounded DAG capacity")
		}
		sourceOrder = append(sourceOrder, order...)
		calls, err := discoverDirectVisualCalls(string(source))
		if err != nil {
			return fmt.Errorf("source/DAG: selected source %q: %w", name, err)
		}
		for step, kinds := range calls {
			if step == "" {
				if directCalls[step] == nil {
					directCalls[step] = map[string]int{}
				}
				for key, count := range kinds {
					directCalls[step][key] += count
				}
			} else {
				directCalls[step] = kinds
			}
		}
	}
	if emptyDAG {
		if err := requireVisualDAG(discovered); err != nil {
			return err
		}
		return validateDirectVisualCalls(nil, directCalls)
	}
	if err := validateSourceDAGNodes(nodes, discovered); err != nil {
		return err
	}
	if err := validateSourceDAGOrder(dag, sourceOrder); err != nil {
		return err
	}
	return validateDirectVisualCalls(flows, directCalls)
}

func declaredStepFlows(dag []byte) ([]flowblocks.StepFlow, error) {
	// Registry validates the same 1 MiB maximum before a build. Keep this
	// independent source/DAG entry point bounded too, including legacy callers.
	projection := flowblocks.FromDAG(dag, 1<<20)
	if !projection.Complete {
		return nil, fmt.Errorf("source/DAG: visual_flow is invalid or the DAG exceeds the bounded projection")
	}
	return projection.Steps, nil
}

// validateDirectVisualCalls verifies lexical source evidence: each declared
// built-in operation must have one direct SDK helper call in its Step closure.
// Custom blocks remain author-declared review annotations. When a
// merge declares a mode and bound, its helper and literal arguments must match
// too. This does not prove a call executed or validate data values or edges.
// VisualSourceMismatch lets retained-source proof distinguish a visual-only
// annotation error from a source/DAG durable-node mismatch. New authoring
// rejects both; legacy published artifacts can retain executable integrity
// while their block graph is marked unverified.
type VisualSourceMismatch struct{ Err error }

func (e *VisualSourceMismatch) Error() string { return e.Err.Error() }
func (e *VisualSourceMismatch) Unwrap() error { return e.Err }

func validateDirectVisualCalls(flows []flowblocks.StepFlow, calls map[string]map[string]int) error {
	if err := compareDirectVisualCalls(flows, calls); err != nil {
		return &VisualSourceMismatch{Err: err}
	}
	return nil
}

func compareDirectVisualCalls(flows []flowblocks.StepFlow, calls map[string]map[string]int) error {
	for _, flow := range flows {
		if calls[flow.Step]["invalid:split_nil_predicate"] > 0 {
			return fmt.Errorf("source/DAG visual_flow mismatch: step %q calls sdk/blocks.Split or SplitObserved with a nil predicate; no branch decision can be reviewed", flow.Step)
		}
		expected := make(map[string]int, len(checkedVisualKinds))
		expectedModes := make(map[string]int)
		declaredObserved := make(map[string]int)
		for _, block := range flow.Blocks {
			if !supportsDirectVisualEvidence(block.Kind) {
				return fmt.Errorf("source/DAG visual_flow mismatch: unsupported built-in block kind %q in step %q", block.Kind, flow.Step)
			}
			expected[block.Kind]++
			if block.Kind == "merge" && block.Mode != "" {
				expectedModes[visualModeKey(block.Mode, block.MaxRows)]++
				declaredObserved[visualObservedKey(block.ID, block.Mode, block.MaxRows)] = 1
			}
			if block.Kind == "split" || block.Kind == "iterate" || block.Kind == "aggregate" {
				declaredObserved[visualObservedSimpleKey(block.Kind, block.ID)] = 1
			}
		}
		for _, kind := range checkedVisualKinds {
			if kind == "merge" {
				continue // Zip and JoinByKey can represent their own visual kinds.
			}
			got := calls[flow.Step][kind]
			if expected[kind] != got {
				return fmt.Errorf("source/DAG visual_flow mismatch: step %q declares %d %s blocks but its Step closure has %d direct sdk/blocks.%s calls; helper calls in separate functions are not static evidence for this step", flow.Step, expected[kind], kind, got, visualHelperName(kind))
			}
		}
		mergeFamily := expected["merge"] + expected["zip"] + expected["join"]
		if got := calls[flow.Step]["merge"]; got != mergeFamily {
			if expected["zip"] == 0 && expected["join"] == 0 {
				return fmt.Errorf("source/DAG visual_flow mismatch: step %q declares %d merge blocks but its Step closure has %d direct sdk/blocks.Merge calls; helper calls in separate functions are not static evidence for this step", flow.Step, expected["merge"], got)
			}
			return fmt.Errorf("source/DAG visual_flow mismatch: step %q declares %d merge/zip/join blocks but its Step closure has %d direct merge-family SDK helper calls", flow.Step, mergeFamily, got)
		}
		modeKeys := make([]string, 0, len(expectedModes))
		for key := range expectedModes {
			modeKeys = append(modeKeys, key)
		}
		sort.Strings(modeKeys)
		for _, key := range modeKeys {
			if got := calls[flow.Step][key]; got < expectedModes[key] {
				return fmt.Errorf("source/DAG visual_flow mismatch: step %q declares %d merge blocks with %s but source has %d direct matching helper calls", flow.Step, expectedModes[key], strings.TrimPrefix(key, "mode:"), got)
			}
		}
		// A typed positional merge consumes one Zip call. A visual zip needs
		// another direct Zip call; it cannot borrow the typed merge's evidence.
		if needed := expected["zip"] + expectedModes[visualModeKey("position_truncate", 0)]; calls[flow.Step]["helper:Zip"] < needed {
			return fmt.Errorf("source/DAG visual_flow mismatch: step %q declares %d zip blocks without enough direct sdk/blocks.Zip calls after typed merges", flow.Step, expected["zip"])
		}
		// Observed joins are reserved for their exact typed merge declaration.
		// An untyped visual join needs a separate ordinary JoinByKey call.
		plainJoinsNeeded := expected["join"]
		for key, count := range expectedModes {
			if strings.HasPrefix(key, "mode:inner_join:") || strings.HasPrefix(key, "mode:left_join:") || strings.HasPrefix(key, "mode:right_join:") || strings.HasPrefix(key, "mode:full_join:") {
				observed := calls[flow.Step]["observed_"+key]
				if observed < count {
					plainJoinsNeeded += count - observed
				}
			}
		}
		if calls[flow.Step]["helper:JoinByKey"] < plainJoinsNeeded {
			return fmt.Errorf("source/DAG visual_flow mismatch: step %q declares %d join blocks without enough direct sdk/blocks.JoinByKey calls after typed merges", flow.Step, expected["join"])
		}
		for key, count := range calls[flow.Step] {
			if strings.HasPrefix(key, "observed:") && count > declaredObserved[key] {
				return fmt.Errorf("source/DAG visual_flow mismatch: observed block id and shape must match one declaration in step %q", flow.Step)
			}
		}
		matchedObserved := 0
		for key, count := range calls[flow.Step] {
			if strings.HasPrefix(key, "observed:") {
				matchedObserved += count
			}
		}
		if matchedObserved != calls[flow.Step]["observed_total"] {
			return fmt.Errorf("source/DAG visual_flow mismatch: observed block requires a literal block id and matching shape in step %q", flow.Step)
		}
	}
	declaredSteps := make(map[string]bool, len(flows))
	for _, flow := range flows {
		declaredSteps[flow.Step] = true
	}
	directObserved := 0
	for step, kinds := range calls {
		if step == "" {
			continue
		}
		if kinds["observed_total"] > 0 && !declaredSteps[step] {
			return fmt.Errorf("source/DAG visual_flow mismatch: observed block in step %q requires a matching visual_flow declaration", step)
		}
		directObserved += kinds["observed_total"]
	}
	if directObserved != calls[""]["observed_global"] {
		return fmt.Errorf("source/DAG visual_flow mismatch: observed block must be a direct call inside a declared Step closure")
	}
	return nil
}

func supportsDirectVisualEvidence(kind string) bool {
	if kind == "custom" || kind == "zip" || kind == "join" {
		return true
	}
	for _, checked := range checkedVisualKinds {
		if kind == checked {
			return true
		}
	}
	return false
}

func visualModeKey(mode string, maxRows int) string {
	return fmt.Sprintf("mode:%s:%d", mode, maxRows)
}

func visualObservedKey(blockID, mode string, maxRows int) string {
	return fmt.Sprintf("observed:%s:%s:%d", blockID, mode, maxRows)
}

func visualObservedSimpleKey(kind, blockID string) string {
	return "observed:" + kind + ":" + blockID
}

func isObservedVisualHelper(helper string) bool {
	switch helper {
	case "JoinByKeyObserved", "SplitObserved", "IterateObserved", "AggregateObserved":
		return true
	}
	return false
}

func visualHelperName(kind string) string {
	switch kind {
	case "split":
		return "Split"
	case "iterate":
		return "Iterate"
	case "aggregate":
		return "Aggregate"
	case "merge":
		return "Merge"
	case "if":
		return "If"
	case "switch":
		return "Switch"
	case "map":
		return "Map"
	case "filter":
		return "Filter"
	case "reduce":
		return "Reduce"
	case "group_by":
		return "GroupBy"
	case "sort":
		return "SortBy"
	case "limit":
		return "Limit"
	case "chunk":
		return "Chunk"
	case "flatten":
		return "Flatten"
	case "unique":
		return "UniqueBy"
	case "coalesce":
		return "Coalesce"
	default:
		return ""
	}
}

// discoverDirectVisualCalls inspects the function literal supplied directly
// to each Step. Calls inside a separate function or nested closure are not
// counted: without interprocedural analysis they cannot be tied to this step.
func discoverDirectVisualCalls(source string) (map[string]map[string]int, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "workflow.go", source, 0)
	if err != nil {
		return nil, fmt.Errorf("source/DAG: parse workflow source: %w", err)
	}
	sdkAliases, importedNames, sdkDotImport := sdkImportAliases(f)
	flowReceivers := sdkFlowReceivers(f, sdkAliases, sdkDotImport)
	blockAliases := map[string]bool{}
	blockDotImport := false
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != reactorBlocksImportPath {
			continue
		}
		alias := "blocks"
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "." {
			blockDotImport = true
		} else if alias != "_" {
			blockAliases[alias] = true
		}
	}
	out := make(map[string]map[string]int)
	globalObserved := 0
	ast.Inspect(f, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			helper := directVisualHelper(call.Fun, blockAliases, blockDotImport)
			if isObservedVisualHelper(helper) {
				globalObserved++
			}
		}
		return true
	})
	out[""] = map[string]int{"observed_global": globalObserved}
	ast.Inspect(f, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		_, nameArg, kind, recognized := workflowNodeCall(call.Fun, sdkAliases, importedNames, sdkDotImport, flowReceivers)
		if !recognized || kind != "step" || len(call.Args) <= nameArg+2 {
			return true
		}
		name, ok := call.Args[nameArg].(*ast.BasicLit)
		if !ok || name.Kind != token.STRING {
			return true // discoverSourceNodes reports the dynamic-name error.
		}
		step, err := strconv.Unquote(name.Value)
		if err != nil {
			return true
		}
		closure, ok := call.Args[nameArg+2].(*ast.FuncLit)
		if !ok {
			out[step] = nil
			return true
		}
		counts := make(map[string]int, len(checkedVisualKinds))
		ast.Inspect(closure.Body, func(inner ast.Node) bool {
			if _, nested := inner.(*ast.FuncLit); nested {
				return false
			}
			if helperCall, ok := inner.(*ast.CallExpr); ok {
				if helper := directVisualHelper(helperCall.Fun, blockAliases, blockDotImport); helper != "" {
					kind := directVisualHelpers[helper]
					counts[kind]++
					counts["helper:"+helper]++
					if (helper == "Split" && len(helperCall.Args) == 2 && isLiteralNil(helperCall.Args[1])) ||
						(helper == "SplitObserved" && len(helperCall.Args) == 4 && isLiteralNil(helperCall.Args[3])) {
						counts["invalid:split_nil_predicate"]++
					}
					if isObservedVisualHelper(helper) {
						counts["observed_total"]++
					}
					if helper == "SplitObserved" || helper == "IterateObserved" || helper == "AggregateObserved" {
						blockID := ""
						wantedArgs := 4
						if helper == "AggregateObserved" {
							wantedArgs = 5
						}
						if len(helperCall.Args) == wantedArgs {
							if lit, ok := helperCall.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								blockID, _ = strconv.Unquote(lit.Value)
							}
						}
						counts[visualObservedSimpleKey(kind, blockID)]++
					}
					if mode, maxRows, matched := literalMergeMode(helperCall, helper, blockAliases, blockDotImport); matched {
						counts[visualModeKey(mode, maxRows)]++
						if helper == "JoinByKeyObserved" {
							counts["observed_"+visualModeKey(mode, maxRows)]++
							blockID := ""
							if len(helperCall.Args) == 8 {
								if lit, ok := helperCall.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
									blockID, _ = strconv.Unquote(lit.Value)
								}
							}
							counts[visualObservedKey(blockID, mode, maxRows)]++
						}
					}
				}
			}
			return true
		})
		out[step] = counts
		return true
	})
	return out, nil
}

func directVisualHelper(fun ast.Expr, aliases map[string]bool, dotImport bool) string {
	for {
		switch indexed := fun.(type) {
		case *ast.IndexExpr:
			fun = indexed.X
		case *ast.IndexListExpr:
			fun = indexed.X
		default:
			goto unwrapped
		}
	}
unwrapped:
	if selector, ok := fun.(*ast.SelectorExpr); ok {
		pkg, ok := selector.X.(*ast.Ident)
		// The parser resolves a shadowing local variable to a non-nil Obj.
		// Imported package selectors remain nil until type checking.
		if ok && pkg.Obj == nil && aliases[pkg.Name] {
			if directVisualHelpers[selector.Sel.Name] != "" {
				return selector.Sel.Name
			}
		}
	}
	if ident, ok := fun.(*ast.Ident); ok && dotImport && ident.Obj == nil {
		if directVisualHelpers[ident.Name] != "" {
			return ident.Name
		}
	}
	return ""
}

// literalMergeMode recognizes the exact helper and literal options a typed
// visual merge block can truthfully display. Dynamic mode/limit expressions
// remain valid Go but cannot be verified as this static annotation.
func literalMergeMode(call *ast.CallExpr, helper string, aliases map[string]bool, dotImport bool) (string, int, bool) {
	switch helper {
	case "Merge", "Append":
		return "append", 0, true
	case "MergeByKey":
		return "left_enrich_last_right", 0, true
	case "Zip":
		return "position_truncate", 0, true
	case "MergeMaps":
		return "map_override", 0, true
	case "CrossJoin", "ZipAll":
		if len(call.Args) != 3 {
			return "", 0, false
		}
		bound, ok := literalPositiveInt(call.Args[2])
		if !ok {
			return "", 0, false
		}
		if helper == "CrossJoin" {
			return "all_pairs", bound, true
		}
		return "position_keep_all", bound, true
	case "JoinByKey", "JoinByKeyObserved":
		modeIndex, boundIndex, wantedArgs := 4, 5, 6
		if helper == "JoinByKeyObserved" {
			modeIndex, boundIndex, wantedArgs = 6, 7, 8
		}
		if len(call.Args) != wantedArgs {
			return "", 0, false
		}
		mode := directVisualHelperConstant(call.Args[modeIndex], aliases, dotImport)
		bound, ok := literalPositiveInt(call.Args[boundIndex])
		if !ok {
			return "", 0, false
		}
		switch mode {
		case "JoinInner":
			return "inner_join", bound, true
		case "JoinLeft":
			return "left_join", bound, true
		case "JoinRight":
			return "right_join", bound, true
		case "JoinFull":
			return "full_join", bound, true
		}
	}
	return "", 0, false
}

func directVisualHelperConstant(expr ast.Expr, aliases map[string]bool, dotImport bool) string {
	if selector, ok := expr.(*ast.SelectorExpr); ok {
		pkg, ok := selector.X.(*ast.Ident)
		if ok && pkg.Obj == nil && aliases[pkg.Name] {
			return selector.Sel.Name
		}
	}
	if ident, ok := expr.(*ast.Ident); ok && dotImport && ident.Obj == nil {
		return ident.Name
	}
	return ""
}

func literalPositiveInt(expr ast.Expr) (int, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.ParseInt(literal.Value, 0, 64)
	if err != nil || n < 1 || n > sdkblocks.MaxJoinRows {
		return 0, false
	}
	return int(n), true
}

func isLiteralNil(expr ast.Expr) bool {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			break
		}
		expr = paren.X
	}
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil" && ident.Obj == nil
}

// requireVisualDAG prevents a durable executable node from becoming
// invisible in the review flow. A plain Go workflow with no Reactor control
// calls may still use the legacy empty DAG; once the source contains Step,
// SideEffect, Sleep, or AwaitSignal, the author must provide the graph that
// describes those calls.
func requireVisualDAG(discovered map[string]string) error {
	if len(discovered) == 0 {
		return nil
	}
	names := make([]string, 0, len(discovered))
	for name := range discovered {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Errorf("source/DAG: source contains durable nodes (%s); provide a visual DAG", strings.Join(names, ", "))
}

func validateSourceDAGNodes(nodes, discovered map[string]string) error {

	missing := make([]string, 0)
	for name := range discovered {
		if _, ok := nodes[name]; !ok {
			missing = append(missing, name)
		}
	}
	extra := make([]string, 0)
	for name := range nodes {
		if _, ok := discovered[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		parts := make([]string, 0, 2)
		if len(missing) > 0 {
			parts = append(parts, "source calls missing from DAG: "+strings.Join(missing, ", "))
		}
		if len(extra) > 0 {
			parts = append(parts, "DAG nodes missing from source: "+strings.Join(extra, ", "))
		}
		return fmt.Errorf("source/DAG mismatch: %s", strings.Join(parts, "; "))
	}
	for name, wantKind := range discovered {
		if gotKind := nodes[name]; gotKind != "" && gotKind != wantKind {
			return fmt.Errorf("source/DAG mismatch: node %q has kind %q in DAG, source requires %q", name, gotKind, wantKind)
		}
	}
	return nil
}

func declaredDAGNodes(raw []byte) (map[string]string, error) {
	var doc struct {
		Steps []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"steps"`
		Nodes []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("source/DAG: parse: %w", err)
	}
	out := make(map[string]string, len(doc.Steps)+len(doc.Nodes))
	for _, step := range doc.Steps {
		if step.Name != "" {
			out[step.Name] = step.Kind
		}
	}
	for _, node := range doc.Nodes {
		name := node.ID
		if name == "" {
			name = node.Name
		}
		if name != "" {
			out[name] = node.Kind
		}
	}
	return out, nil
}

func discoverSourceNodes(source string) (map[string]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "workflow.go", source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("source/DAG: parse workflow source: %w", err)
	}
	sdkAliases, importedNames, sdkDotImport := sdkImportAliases(f)
	flowReceivers := sdkFlowReceivers(f, sdkAliases, sdkDotImport)
	out := make(map[string]string)
	var walkErr error
	ast.Inspect(f, func(node ast.Node) bool {
		if walkErr != nil || node == nil {
			return walkErr == nil
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		_, argIndex, kind, recognized := workflowNodeCall(call.Fun, sdkAliases, importedNames, sdkDotImport, flowReceivers)
		if !recognized {
			return true
		}
		if len(call.Args) <= argIndex {
			walkErr = fmt.Errorf("source/DAG: %s call is missing its node name", kind)
			return false
		}
		literal, ok := call.Args[argIndex].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			walkErr = fmt.Errorf("source/DAG: %s node name must be a string literal so the flow can be represented", kind)
			return false
		}
		nodeName, err := strconv.Unquote(literal.Value)
		if err != nil || strings.TrimSpace(nodeName) == "" {
			walkErr = fmt.Errorf("source/DAG: %s node name must be a non-empty string literal", kind)
			return false
		}
		if previous, exists := out[nodeName]; exists {
			walkErr = fmt.Errorf("source/DAG: node %q is declared by both %s and %s calls", nodeName, previous, kind)
			return false
		}
		out[nodeName] = kind
		return true
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}

func sdkImportAliases(f *ast.File) (map[string]bool, map[string]bool, bool) {
	// The SDK package is commonly imported as reactor, but valid workflow
	// sources may use an explicit alias (for example, `r`).  Keep the static
	// source/DAG check aligned with the compiler by resolving aliases from the
	// import declaration instead of treating every `.Step` selector as a
	// Flow method call.  Without this, r.Step(flow, ctx, name, ...) was read at
	// the method argument position (ctx), and a valid workflow was rejected or
	// its visual node went missing.
	sdkAliases := map[string]bool{}
	importedNames := map[string]bool{}
	sdkDotImport := false
	for _, spec := range f.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		alias := importPath[strings.LastIndex(importPath, "/")+1:]
		// The SDK package declares its package name as reactor even though its
		// import path ends in /sdk; mirror Go's default import name here.
		if importPath == reactorSDKImportPath {
			alias = "reactor"
		}
		if spec.Name != nil {
			if importPath == reactorSDKImportPath && spec.Name.Name == "." {
				sdkDotImport = true
			}
			alias = spec.Name.Name
		}
		if alias != "_" && alias != "." {
			importedNames[alias] = true
		}
		if importPath == reactorSDKImportPath && alias != "_" && alias != "." {
			sdkAliases[alias] = true
		}
	}
	return sdkAliases, importedNames, sdkDotImport
}

// workflowNodeCall returns the node-name argument index and visual kind for
// the SDK's durable control-flow calls. Generic Step[T] is represented by an
// IndexExpr/IndexListExpr, which must be unwrapped before checking the import.
func sdkFlowReceivers(file *ast.File, sdkAliases map[string]bool, sdkDotImport bool) map[*ast.Object]bool {
	flowType := func(expr ast.Expr) bool {
		if selector, ok := expr.(*ast.SelectorExpr); ok && selector.Sel.Name == "Flow" {
			pkg, ok := selector.X.(*ast.Ident)
			return ok && pkg.Obj == nil && sdkAliases[pkg.Name]
		}
		ident, ok := expr.(*ast.Ident)
		return ok && ident.Name == "Flow" && ident.Obj == nil && sdkDotImport
	}
	receivers := make(map[*ast.Object]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		var names []*ast.Ident
		switch declaration := node.(type) {
		case *ast.Field:
			if flowType(declaration.Type) {
				names = declaration.Names
			}
		case *ast.ValueSpec:
			if flowType(declaration.Type) {
				names = declaration.Names
			}
		}
		for _, name := range names {
			if name.Obj != nil {
				receivers[name.Obj] = true
			}
		}
		return true
	})
	// A new variable inferred directly from a Flow retains the SDK Flow
	// interface type. Preserve ordinary aliases while refusing unrelated
	// methods that merely share Step/Sleep/AwaitSignal names.
	for changed := true; changed; {
		changed = false
		markAlias := func(target, source ast.Expr, declaration ast.Node) {
			from, fromOK := source.(*ast.Ident)
			to, toOK := target.(*ast.Ident)
			if !fromOK || !toOK || from.Obj == nil || to.Obj == nil || !receivers[from.Obj] || to.Obj.Decl != declaration || receivers[to.Obj] {
				return
			}
			receivers[to.Obj] = true
			changed = true
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch declaration := node.(type) {
			case *ast.AssignStmt:
				if declaration.Tok == token.DEFINE && len(declaration.Lhs) == len(declaration.Rhs) {
					for i := range declaration.Lhs {
						markAlias(declaration.Lhs[i], declaration.Rhs[i], declaration)
					}
				}
			case *ast.ValueSpec:
				if declaration.Type == nil && len(declaration.Names) == len(declaration.Values) {
					for i := range declaration.Names {
						markAlias(declaration.Names[i], declaration.Values[i], declaration)
					}
				}
			}
			return true
		})
	}
	return receivers
}

func workflowNodeCall(fun ast.Expr, sdkAliases, importedNames map[string]bool, sdkDotImport bool, flowReceivers map[*ast.Object]bool) (string, int, string, bool) {
	for {
		switch indexed := fun.(type) {
		case *ast.IndexExpr:
			fun = indexed.X
		case *ast.IndexListExpr:
			fun = indexed.X
		default:
			goto unwrapped
		}
	}
unwrapped:
	if sdkDotImport {
		if ident, ok := fun.(*ast.Ident); ok && ident.Obj == nil {
			switch ident.Name {
			case "Step":
				return ident.Name, 2, "step", true
			case "SideEffect":
				return ident.Name, 2, "side_effect", true
			}
		}
	}
	sel, ok := selectorCall(fun)
	if !ok {
		return "", 0, "", false
	}
	// A method-shaped selector such as time.Sleep is not a Reactor durable
	// node. Reject selectors rooted at known non-SDK imports before applying the
	// method-name fallback, otherwise ordinary helper code is reported as a
	// missing visual node and can mask the real lint diagnostic.
	if pkg, ok := sel.X.(*ast.Ident); ok && importedNames[pkg.Name] && (!sdkAliases[pkg.Name] || pkg.Obj != nil) {
		// A local variable may shadow an SDK import alias. Its methods are not
		// package functions and must not receive the SDK argument positions.
		return "", 0, "", false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Obj == nil && sdkAliases[pkg.Name] {
		switch sel.Sel.Name {
		case "Step":
			return sel.Sel.Name, 2, "step", true
		case "SideEffect":
			return sel.Sel.Name, 2, "side_effect", true
		}
	}
	receiver, ok := sel.X.(*ast.Ident)
	if !ok || receiver.Obj == nil || !flowReceivers[receiver.Obj] {
		return "", 0, "", false
	}
	switch sel.Sel.Name {
	case "Step":
		return sel.Sel.Name, 1, "step", true
	case "Sleep":
		return sel.Sel.Name, 1, "sleep", true
	case "AwaitSignal":
		return sel.Sel.Name, 1, "await_signal", true
	default:
		return "", 0, "", false
	}
}

func selectorCall(expr ast.Expr) (*ast.SelectorExpr, bool) {
	switch call := expr.(type) {
	case *ast.SelectorExpr:
		return call, true
	case *ast.IndexExpr:
		return selectorCall(call.X)
	case *ast.IndexListExpr:
		return selectorCall(call.X)
	default:
		return nil, false
	}
}
