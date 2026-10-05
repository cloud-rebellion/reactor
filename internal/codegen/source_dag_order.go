package codegen

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// A validated DAG has at most 256 executable nodes. A source with more
// distinct direct-call order pairs cannot match that DAG, so stop before an
// untrusted authoring request allocates a quadratic, unbounded pair list.
const maxDefiniteSourceOrderPairs = 256 * 256

// validateSourceDAGOrder rejects only a dependency contradiction that can be
// proved from source syntax. If two durable SDK calls are direct statements in
// one Go block, every execution that reaches both calls reaches the first one
// first. The DAG cannot truthfully require the later call before the earlier
// one. Calls hidden in branches, helpers, argument expressions, or separate
// blocks give no such static guarantee and remain author-declared.
func validateSourceDAGOrder(dag []byte, pairs [][2]string) error {
	if len(pairs) == 0 {
		return nil
	}
	var declared struct {
		Steps []struct {
			Name      string   `json:"name"`
			DependsOn []string `json:"depends_on"`
		} `json:"steps"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(dag, &declared); err != nil {
		return fmt.Errorf("source/DAG: parse dependencies: %w", err)
	}
	// An edge points from prerequisite to dependent. Reachability includes
	// indirect prerequisites so A, B, C in source cannot be drawn as C -> B -> A.
	adjacent := make(map[string][]string)
	for _, step := range declared.Steps {
		for _, dependency := range step.DependsOn {
			adjacent[dependency] = append(adjacent[dependency], step.Name)
		}
	}
	for _, edge := range declared.Edges {
		adjacent[edge.From] = append(adjacent[edge.From], edge.To)
	}
	if len(adjacent) == 0 {
		return nil
	}
	reachability := make(map[string]map[string]bool)
	for _, pair := range pairs {
		earlier, later := pair[0], pair[1]
		reachable, computed := reachability[later]
		if !computed {
			reachable = make(map[string]bool)
			stack := append([]string(nil), adjacent[later]...)
			for len(stack) > 0 {
				current := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if reachable[current] {
					continue
				}
				reachable[current] = true
				stack = append(stack, adjacent[current]...)
			}
			reachability[later] = reachable
		}
		if reachable[earlier] {
			return fmt.Errorf("source/DAG dependency order mismatch: source calls %q before %q in the same block, but the DAG requires %q before %q", earlier, later, later, earlier)
		}
	}
	return nil
}

// definiteSourceCallOrder records only direct durable-call expressions in
// sequential statements. In particular it never turns lexical order across
// if/switch branches or helper function boundaries into execution evidence.
func definiteSourceCallOrder(source string) ([][2]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "workflow.go", source, 0)
	if err != nil {
		return nil, fmt.Errorf("source/DAG: parse workflow source: %w", err)
	}
	sdkAliases, importedNames, sdkDotImport := sdkImportAliases(file)
	flowReceivers := sdkFlowReceivers(file, sdkAliases, sdkDotImport)
	var pairs [][2]string
	exceeded := false
	ast.Inspect(file, func(node ast.Node) bool {
		if exceeded {
			return false
		}
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		var earlier []string
		for _, statement := range block.List {
			for _, name := range directStatementDurableNames(statement, sdkAliases, importedNames, sdkDotImport, flowReceivers) {
				for _, previous := range earlier {
					if len(pairs) >= maxDefiniteSourceOrderPairs {
						exceeded = true
						return false
					}
					pairs = append(pairs, [2]string{previous, name})
				}
				earlier = append(earlier, name)
			}
		}
		return true
	})
	if exceeded {
		return nil, fmt.Errorf("source/DAG: durable call order exceeds bounded DAG capacity")
	}
	return pairs, nil
}

func directStatementDurableNames(statement ast.Stmt, sdkAliases, importedNames map[string]bool, sdkDotImport bool, flowReceivers map[*ast.Object]bool) []string {
	var expressions []ast.Expr
	switch stmt := statement.(type) {
	case *ast.AssignStmt:
		expressions = stmt.Rhs
	case *ast.ExprStmt:
		expressions = []ast.Expr{stmt.X}
	case *ast.ReturnStmt:
		expressions = stmt.Results
	case *ast.DeclStmt:
		if declaration, ok := stmt.Decl.(*ast.GenDecl); ok {
			for _, spec := range declaration.Specs {
				if value, ok := spec.(*ast.ValueSpec); ok {
					expressions = append(expressions, value.Values...)
				}
			}
		}
	}
	var names []string
	for _, expression := range expressions {
		call, ok := expression.(*ast.CallExpr)
		if !ok {
			continue
		}
		_, argIndex, _, recognized := workflowNodeCall(call.Fun, sdkAliases, importedNames, sdkDotImport, flowReceivers)
		if !recognized || len(call.Args) <= argIndex {
			continue
		}
		literal, ok := call.Args[argIndex].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		name, err := strconv.Unquote(literal.Value)
		if err == nil && name != "" {
			names = append(names, name)
		}
	}
	return names
}
