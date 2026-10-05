package mcp

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const (
	maxMCPDependencyGoFiles     = 32
	maxMCPDependencySourceBytes = 2 << 20
	maxMCPDependencyRefs        = 64
	maxMCPDependencyIDBytes     = 256
	maxMCPDependencyCacheItems  = 128
)

type dependencySourceScan struct {
	refs         []string
	dynamicCalls int
	truncated    bool
}

// The source proof is rechecked on every review/preflight, but a successful
// parse of its immutable, manifest-pinned files can be reused. This keeps MCP
// dispatch admission from reparsing Go on every run while grants and OAuth
// status are still read live for every receipt.
var dependencySourceCache = struct {
	sync.Mutex
	items map[string]dependencySourceScan
	order []string
}{items: make(map[string]dependencySourceScan)}

// dependencyReadiness is an advisory inspection of direct SDK calls in the
// immutable, build-selected source. Go can compute IDs at runtime or call SDK
// functions through wrappers, so even a fully checked result is not a proof
// that every runtime dependency has been found.
type dependencyReadiness struct {
	status              string
	required            []string
	missingGrants       []string
	unresolvedCount     int
	inactiveConnections []string
	dynamicCalls        int
	truncated           bool
	checkFailed         bool
}

func (d dependencyReadiness) blocked() bool {
	return len(d.missingGrants) > 0 || d.unresolvedCount > 0 || len(d.inactiveConnections) > 0
}

func (d dependencyReadiness) view() map[string]any {
	return map[string]any{
		"status":                     d.status,
		"coverage":                   "direct_literal_sdk_calls_only",
		"required_credential_ids":    d.required,
		"missing_grants":             d.missingGrants,
		"unresolved_reference_count": d.unresolvedCount,
		"inactive_connections":       d.inactiveConnections,
		"dynamic_call_count":         d.dynamicCalls,
		"truncated":                  d.truncated,
		"note":                       "Only direct SDK calls with literal credential IDs in verified, build-selected Go files are checked. Runtime-computed IDs and wrapper calls may not be found; live execution rechecks tenant, grant, and connection state. No credential values are read.",
	}
}

// workflowDependencyReadiness intentionally accepts the already checked source
// proof status from review/preflight. It never interprets an unverified or
// legacy source tree as evidence of a complete dependency inventory.
func (s *Server) workflowDependencyReadiness(ctx context.Context, slug, workflowID, artifactSHA256, sourceManifestSHA256, sourceDAGStatus string) dependencyReadiness {
	d := dependencyReadiness{status: "unavailable", required: []string{}, missingGrants: []string{}, inactiveConnections: []string{}}
	if sourceDAGStatus != "verified" || artifactSHA256 == "" {
		return d
	}
	scan, ok := s.scanWorkflowDependencySource(ctx, slug, artifactSHA256, sourceManifestSHA256)
	if !ok {
		return d
	}
	d.dynamicCalls, d.truncated = scan.dynamicCalls, scan.truncated
	for _, id := range scan.refs {
		if ctx.Err() != nil {
			d.status, d.checkFailed = "unknown", true
			return d
		}
		owner, ownerErr := s.Journal.SecretTenant(ctx, id)
		if errors.Is(ownerErr, journal.ErrNotFound) || (ownerErr == nil && owner != s.tenantID(ctx)) {
			// Source literals are untrusted. An unresolved string might be a
			// pasted secret rather than an ID, so return only a count until a
			// same-tenant metadata row establishes it as a credential ID.
			d.unresolvedCount++
			continue
		}
		if ownerErr != nil {
			d.checkFailed = true
			continue
		}
		d.required = append(d.required, id)
		granted, grantErr := s.Journal.HasGrant(ctx, workflowID, id)
		if errors.Is(grantErr, journal.ErrACLEmpty) || (grantErr == nil && !granted) {
			d.missingGrants = append(d.missingGrants, id)
		} else if grantErr != nil {
			d.checkFailed = true
		}
		if connectionID, isOAuth := strings.CutPrefix(id, journal.OAuthSecretPrefix); isOAuth {
			if s.OAuth == nil {
				d.checkFailed = true
				continue
			}
			providerID, providerErr := s.OAuth.ConnectionProvider(ctx, connectionID, s.tenantID(ctx))
			if providerErr != nil {
				d.checkFailed = true
				continue
			}
			active, activeErr := s.OAuth.ConnectionActive(ctx, s.tenantID(ctx), connectionID, providerID)
			if activeErr != nil {
				d.checkFailed = true
			} else if !active {
				d.inactiveConnections = append(d.inactiveConnections, id)
			}
		}
	}
	switch {
	case d.blocked():
		d.status = "missing"
	case d.checkFailed:
		d.status = "unknown"
	case d.dynamicCalls > 0 || d.truncated:
		d.status = "partial"
	default:
		d.status = "checked_static_calls"
	}
	return d
}

func (s *Server) scanWorkflowDependencySource(ctx context.Context, slug, artifactSHA256, sourceManifestSHA256 string) (dependencySourceScan, bool) {
	key := strings.Join([]string{filepath.Clean(s.StateRoot), s.tenantID(ctx), slug, artifactSHA256, sourceManifestSHA256}, "\x00")
	dependencySourceCache.Lock()
	cached, found := dependencySourceCache.items[key]
	dependencySourceCache.Unlock()
	if found {
		return cached, true
	}
	artifactPath, err := s.artifactPathForTenant(ctx, slug, artifactSHA256)
	if err != nil {
		return dependencySourceScan{}, false
	}
	sourceDir := filepath.Join(filepath.Dir(artifactPath), "source")
	files, selected, err := registry.SourceManifestCompiledGoFiles(sourceDir)
	if err != nil || !selected || len(files) == 0 || len(files) > maxMCPDependencyGoFiles {
		return dependencySourceScan{}, false
	}
	refs := make(map[string]struct{})
	var result dependencyReadiness
	var totalBytes int
	for _, name := range files {
		if ctx.Err() != nil {
			return dependencySourceScan{}, false
		}
		// The source proof verified these exact paths against the pinned
		// manifest. The bounded reader also rejects symlinks and special files.
		contents, truncated, size, readErr := readBoundedMCPFile(filepath.Join(sourceDir, filepath.FromSlash(name)), maxMCPWorkflowSourceBytes)
		if readErr != nil || truncated || size > maxMCPDependencySourceBytes-totalBytes {
			return dependencySourceScan{}, false
		}
		totalBytes += size
		file, parseErr := parser.ParseFile(token.NewFileSet(), name, contents, 0)
		if parseErr != nil {
			return dependencySourceScan{}, false
		}
		collectLiteralSDKRefs(file, refs, &result)
	}
	scan := dependencySourceScan{dynamicCalls: result.dynamicCalls, truncated: result.truncated}
	for id := range refs {
		scan.refs = append(scan.refs, id)
	}
	sort.Strings(scan.refs)
	dependencySourceCache.Lock()
	if _, already := dependencySourceCache.items[key]; !already {
		if len(dependencySourceCache.order) >= maxMCPDependencyCacheItems {
			delete(dependencySourceCache.items, dependencySourceCache.order[0])
			dependencySourceCache.order = dependencySourceCache.order[1:]
		}
		dependencySourceCache.items[key] = scan
		dependencySourceCache.order = append(dependencySourceCache.order, key)
	}
	dependencySourceCache.Unlock()
	return scan, true
}

func collectLiteralSDKRefs(file *ast.File, refs map[string]struct{}, result *dependencyReadiness) {
	const sdk = "github.com/bright-interaction/reactor/sdk/"
	imports := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !strings.HasPrefix(importPath, sdk) {
			continue
		}
		pkg := strings.TrimPrefix(importPath, sdk)
		if pkg != "vault" && pkg != "http" && pkg != "email" {
			continue
		}
		alias := pkg
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "." {
			// Unqualified calls need type resolution; do not infer a ref.
			result.dynamicCalls++
			continue
		}
		if alias != "_" {
			imports[alias] = pkg
		}
	}
	// A local identifier can shadow an import. When one exists, avoid
	// claiming that a same-spelled selector is an SDK call.
	shadowed := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						shadowed[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, name := range n.Names {
				shadowed[name.Name] = true
			}
		case *ast.Field:
			for _, name := range n.Names {
				shadowed[name.Name] = true
			}
		case *ast.RangeStmt:
			if n.Tok == token.DEFINE {
				for _, expr := range []ast.Expr{n.Key, n.Value} {
					if ident, ok := expr.(*ast.Ident); ok {
						shadowed[ident.Name] = true
					}
				}
			}
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkg := imports[ident.Name]
		if pkg == "" {
			return true
		}
		arg := -1
		switch {
		case pkg == "vault" && selector.Sel.Name == "MustGet":
			arg = 0
		case pkg == "vault" && selector.Sel.Name == "Get":
			arg = 1
		case pkg == "http" && selector.Sel.Name == "ConnectorGet":
			arg = 1
		case pkg == "email" && selector.Sel.Name == "SendConnected":
			arg = 1
		default:
			return true
		}
		if shadowed[ident.Name] || len(call.Args) <= arg {
			result.dynamicCalls++
			return true
		}
		literal, ok := call.Args[arg].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			result.dynamicCalls++
			return true
		}
		id, err := strconv.Unquote(literal.Value)
		if err != nil || !safeDependencyID(id) {
			result.dynamicCalls++
			return true
		}
		if _, known := refs[id]; !known {
			if len(refs) >= maxMCPDependencyRefs {
				result.truncated = true
			} else {
				refs[id] = struct{}{}
			}
		}
		return true
	})
}

func safeDependencyID(id string) bool {
	if id == "" || len(id) > maxMCPDependencyIDBytes {
		return false
	}
	for _, ch := range id {
		if ch < '!' || ch > '~' || ch == 92 || ch == 34 || ch == 39 {
			return false
		}
	}
	return true
}
