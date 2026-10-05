package mcp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

const maxMCPWorkflowAuthoringSourceBytes = 4 << 20 // Keep aligned with codegen's main_go input limit.

const workflowRuntimeImport = "github.com/bright-interaction/reactor/sdk/runtime"

// requireMCPWorkflowEntrypoint prevents an AI-authored binary from compiling
// and reporting success while its main function never starts the Reactor pipe
// runtime. Source/DAG matching proves that durable calls occur in compiled Go
// files; it does not prove those calls are reachable from the executable.
// The MCP contract requires the documented direct Serve call in main.go.
func requireMCPWorkflowEntrypoint(mainGo string) error {
	if len(mainGo) > maxMCPWorkflowAuthoringSourceBytes {
		return fmt.Errorf("%w: main_go exceeds %d-byte limit", errInvalidParamsErr, maxMCPWorkflowAuthoringSourceBytes)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", mainGo, 0)
	if err != nil {
		detail, _, _ := boundMCPText(err.Error(), 512)
		return fmt.Errorf("%w: main_go is not valid Go source: %s", errInvalidParamsErr, detail)
	}
	if file.Name == nil || file.Name.Name != "main" {
		return fmt.Errorf("%w: main_go must declare package main", errInvalidParamsErr)
	}

	aliases := make(map[string]struct{})
	dotImported := false
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != workflowRuntimeImport {
			continue
		}
		name := "runtime"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." {
			dotImported = true
		} else if name != "_" {
			aliases[name] = struct{}{}
		}
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil || fn.Name.Name != "main" || fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			expr, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expr.X.(*ast.CallExpr)
			if ok && isMCPWorkflowServeCall(call.Fun, aliases, dotImported) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: main_go must directly call sdk/runtime.Serve(...) from main(); otherwise the executable can exit without running its declared workflow", errInvalidParamsErr)
}

func isMCPWorkflowServeCall(fun ast.Expr, aliases map[string]struct{}, dotImported bool) bool {
	for {
		switch x := fun.(type) {
		case *ast.ParenExpr:
			fun = x.X
		case *ast.IndexExpr:
			fun = x.X
		case *ast.IndexListExpr:
			fun = x.X
		default:
			goto resolved
		}
	}
resolved:
	switch x := fun.(type) {
	case *ast.SelectorExpr:
		alias, ok := x.X.(*ast.Ident)
		if !ok || x.Sel == nil || x.Sel.Name != "Serve" {
			return false
		}
		// The parser resolves lexical shadowing even before go/types runs. A
		// local variable called runtime/rt may have its own Serve method, but
		// it is not the imported Reactor runtime package.
		if alias.Obj != nil && alias.Obj.Kind != ast.Pkg {
			return false
		}
		_, ok = aliases[alias.Name]
		return ok
	case *ast.Ident:
		return dotImported && x.Name == "Serve" && x.Obj == nil
	default:
		return false
	}
}
