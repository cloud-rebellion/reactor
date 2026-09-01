// Package mcp is Reactor's Model Context Protocol surface. It ships a
// stdio JSON-RPC 2.0 transport + read tools (list_workflows, list_runs,
// get_run, get_run_logs, get_analytics, list_dead_letters,
// list_notification_channels, list_credentials, get_credential_audit,
// search_knowledge, query_graph, get_neighbors) so a Claude / Codex /
// similar client can introspect AND debug a running daemon.
//
// Write tools ship behind --allow-write (register_workflow, create_workflow,
// grant_secret, revoke_secret, dispatch_workflow, cancel_run,
// add/revise_knowledge, record_postmortem): create_workflow compiles +
// registers a workflow from supplied Go source (the MCP authoring path, no
// external API key), dispatch_workflow fires a run, cancel_run stops one.
// Read-only is the default so a misbehaving agent can't accidentally fire
// or kill production workflows.
//
// Wire: line-delimited JSON-RPC 2.0 over stdin/stdout. Each line is one
// request OR one response; the server reads requests, dispatches via
// the methods registry, writes responses. No batching, no notifications
// for v1.
//
// Future surfaces:
//   - Resources: status reports, the workflows table, the credential_audit
//     log
//   - Per-tool scopes (workflow:read, vault:read, workflow:write) so a
//     client gets least-privilege access by default.
package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// Protocol version reported during initialize. Mirrors Anthropic's MCP
// spec versioning; bumped on incompatible wire changes.
const ProtocolVersion = "2024-11-05"

// ServerInfo is what the server reports during the initialize handshake.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Server is the MCP dispatcher. Construct with Read/Write surfaces, then
// Serve(reader, writer) blocks until the client closes the pipe.
type Server struct {
	Info        ServerInfo
	Journal     *journal.Journal
	Credentials *credentials.Repo
	Knowledge   *knowledge.Store
	Graph       *graph.Graph
	Log         *slog.Logger

	// Dispatch is the optional write surface. nil means read-only mode;
	// dispatch_workflow returns an error.
	Dispatch DispatchFunc

	// StateRoot is the daemon state dir (workflows/ live under it). When set
	// alongside the write surface, the reactor_create_workflow authoring tool
	// is exposed so an MCP client can compile + register a workflow from Go
	// source it supplies, with no external LLM/API key. Empty disables it.
	StateRoot string

	// PostMortem is the optional auto-DLQ post-mortem trigger. When nil,
	// the reactor_record_postmortem MCP tool returns an error. Wired by
	// the daemon to the in-process postmortem.Generator.
	PostMortem PostMortemFunc

	tools        map[string]toolDef
	registerOnce sync.Once
}

// PostMortemFunc is what reactor_record_postmortem invokes. The daemon
// supplies a closure over its postmortem.Generator so MCP-driven and
// auto-DLQ post-mortems share the same code path.
type PostMortemFunc func(ctx context.Context, runID string) (entryID string, err error)

// DispatchFunc is what mcp.Server calls for the dispatch_workflow write
// tool. The daemon supplies a closure over its in-process Dispatcher so
// MCP triggers and webhook triggers share the same supervisor spawn path.
type DispatchFunc func(ctx context.Context, slug string, payload json.RawMessage) (runID string, err error)

// JSON-RPC 2.0 wire types.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC 2.0 standard error codes.
const (
	errParseError     = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternalError  = -32603
)

// Tool is the JSON-RPC representation of one tool. tools/list returns
// these; tools/call invokes one by name.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// toolDef pairs a Tool with its handler.
type toolDef struct {
	tool    Tool
	handler func(ctx context.Context, args json.RawMessage) (any, error)
}

// Serve reads JSON-RPC requests line-by-line from in and writes
// responses to out. Blocks until in returns io.EOF or out is closed.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Info.Name == "" {
		s.Info.Name = "reactor"
	}
	s.registerTools()

	enc := json.NewEncoder(out)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var writeMu sync.Mutex
	send := func(resp rpcResponse) {
		resp.JSONRPC = "2.0"
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := enc.Encode(resp); err != nil {
			s.Log.Warn("mcp: write failed", "err", err)
		}
	}

	// In-flight handler tracking. Without this, stdin EOF causes Serve
	// to return before async handlers finish writing, dropping their
	// responses on the floor. The waitgroup makes Serve return only
	// after every handler has flushed.
	var wg sync.WaitGroup
	defer wg.Wait()

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			send(rpcResponse{Error: &rpcError{Code: errParseError, Message: err.Error()}})
			continue
		}
		if req.JSONRPC != "2.0" {
			send(rpcResponse{ID: req.ID, Error: &rpcError{Code: errInvalidRequest, Message: "jsonrpc must be 2.0"}})
			continue
		}
		wg.Add(1)
		go func(req rpcRequest) {
			defer wg.Done()
			result, err := s.handle(ctx, req.Method, req.Params)
			if err != nil {
				code := errInternalError
				if errors.Is(err, errMethodNotFoundErr) {
					code = errMethodNotFound
				} else if errors.Is(err, errInvalidParamsErr) {
					code = errInvalidParams
				}
				send(rpcResponse{ID: req.ID, Error: &rpcError{Code: code, Message: err.Error()}})
				return
			}
			// Notifications (id absent) get no response.
			if req.ID == nil {
				return
			}
			send(rpcResponse{ID: req.ID, Result: result})
		}(req)
	}
	return scanner.Err()
}

// errMethodNotFoundErr / errInvalidParamsErr surface JSON-RPC error
// codes through the standard error chain.
var (
	errMethodNotFoundErr = errors.New("mcp: method not found")
	errInvalidParamsErr  = errors.New("mcp: invalid params")
)

// handle dispatches one request to its method handler.
func (s *Server) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": ProtocolVersion,
			"serverInfo":      s.Info,
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		}, nil
	case "tools/list":
		out := make([]Tool, 0, len(s.tools))
		for _, t := range s.tools {
			out = append(out, t.tool)
		}
		return map[string]any{"tools": out}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
		}
		td, ok := s.tools[p.Name]
		if !ok {
			return nil, fmt.Errorf("%w: tool %q", errMethodNotFoundErr, p.Name)
		}
		out, err := td.handler(ctx, p.Arguments)
		if err != nil {
			return map[string]any{
				"content": []any{
					map[string]any{"type": "text", "text": "error: " + scrubToolError(err)},
				},
				"isError": true,
			}, nil
		}
		// Wrap structured output as a JSON text content block per MCP spec.
		raw, _ := json.Marshal(out)
		return map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": string(raw)},
			},
		}, nil
	case "ping":
		return map[string]any{}, nil
	default:
		return nil, fmt.Errorf("%w: %s", errMethodNotFoundErr, method)
	}
}

// scrubToolError genericizes internal-plumbing errors (DB/driver, network
// transport, decrypt) that leak infra detail to the agent, logging the real
// one server-side. It deliberately PRESERVES compiler diagnostics and
// validation messages: create_workflow's go-build stderr is the authoring
// feedback the agent needs to fix its source, so it must pass through.
func scrubToolError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, needle := range []string{
		"dial tcp", "connection refused", "no such host", "i/o timeout",
		"pq:", "SQLSTATE", "sql:", "database is locked",
		"failed to decrypt", "cipher:", "x509:", "tls:",
	} {
		if strings.Contains(msg, needle) {
			slog.Error("reactor mcp internal error", "err", err)
			return "internal error"
		}
	}
	return msg
}

// registerTools populates the tools map. Read tools always register;
// dispatch_workflow only registers when Dispatch is non-nil so
// read-only servers don't advertise a write surface they can't service.
func (s *Server) registerTools() {
	s.tools = map[string]toolDef{}

	s.tools["reactor_list_workflows"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_workflows",
			Description: "List every registered workflow with id, slug, sdk_version, and timestamps.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			return s.Journal.ListWorkflows(ctx)
		},
	}

	s.tools["reactor_list_runs"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_runs",
			Description: "List recent runs newest-first. Optional limit (default 50, max 500).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Limit int `json:"limit"`
			}
			if len(args) > 0 {
				_ = json.Unmarshal(args, &a)
			}
			if a.Limit <= 0 {
				a.Limit = 50
			}
			if a.Limit > 500 {
				a.Limit = 500
			}
			return s.Journal.ListRecentRuns(ctx, a.Limit)
		},
	}

	s.tools["reactor_get_run"] = toolDef{
		tool: Tool{
			Name:        "reactor_get_run",
			Description: "Get one run's metadata + step timeline.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"run_id"},
				"properties": map[string]any{
					"run_id": map[string]any{"type": "string"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				RunID string `json:"run_id"`
			}
			if err := json.Unmarshal(args, &a); err != nil || a.RunID == "" {
				return nil, fmt.Errorf("%w: run_id required", errInvalidParamsErr)
			}
			info, err := s.Journal.GetRun(ctx, a.RunID)
			if err != nil {
				return nil, err
			}
			steps, err := s.Journal.ListSteps(ctx, a.RunID)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"run":   info,
				"steps": steps,
			}, nil
		},
	}

	s.tools["reactor_get_run_logs"] = toolDef{
		tool: Tool{
			Name:        "reactor_get_run_logs",
			Description: "Get a run's persisted log lines (the dispatcher + workflow log tail). Returns lines in order; empty for a run that produced no logs. Lets an AI debug a run it triggered.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"run_id"},
				"properties": map[string]any{
					"run_id": map[string]any{"type": "string"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				RunID string `json:"run_id"`
			}
			if err := json.Unmarshal(args, &a); err != nil || a.RunID == "" {
				return nil, fmt.Errorf("%w: run_id required", errInvalidParamsErr)
			}
			lines, err := s.Journal.GetRunLogs(ctx, a.RunID)
			if err != nil {
				return nil, err
			}
			return map[string]any{"run_id": a.RunID, "lines": lines}, nil
		},
	}

	s.tools["reactor_list_credentials"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_credentials",
			Description: "List every credential with rotation state. Values never leave the daemon.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			creds, err := s.Credentials.List(ctx)
			if err != nil {
				return nil, err
			}
			// Strip RotationTargets; secret_id values are part of the
			// vault surface and shouldn't be exposed via MCP.
			for i := range creds {
				creds[i].RotationTargets = nil
			}
			return creds, nil
		},
	}

	s.tools["reactor_get_credential_audit"] = toolDef{
		tool: Tool{
			Name:        "reactor_get_credential_audit",
			Description: "Read the append-only audit log for one credential. Returns up to limit (default 50) entries newest-first.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"credential_id"},
				"properties": map[string]any{
					"credential_id": map[string]any{"type": "string"},
					"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				CredentialID string `json:"credential_id"`
				Limit        int    `json:"limit"`
			}
			if err := json.Unmarshal(args, &a); err != nil || a.CredentialID == "" {
				return nil, fmt.Errorf("%w: credential_id required", errInvalidParamsErr)
			}
			if a.Limit <= 0 {
				a.Limit = 50
			}
			if a.Limit > 500 {
				a.Limit = 500
			}
			return s.Credentials.ListAudit(ctx, a.CredentialID, a.Limit)
		},
	}

	s.tools["reactor_get_analytics"] = toolDef{
		tool: Tool{
			Name:        "reactor_get_analytics",
			Description: "Get the run-analytics rollup: counts by terminal status, total + succeeded runs, avg + p95 duration, and per-workflow stats. The same numbers the dashboard home shows.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			return s.Journal.AnalyticsSummary(ctx)
		},
	}

	s.tools["reactor_list_dead_letters"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_dead_letters",
			Description: "List dead-letter items (runs whose final attempt failed), newest-first. Lets an AI find what needs a retry. limit defaults to 50.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
					"offset": map[string]any{"type": "integer", "minimum": 0},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				Limit  int `json:"limit"`
				Offset int `json:"offset"`
			}
			_ = json.Unmarshal(args, &a)
			if a.Limit <= 0 {
				a.Limit = 50
			}
			if a.Limit > 500 {
				a.Limit = 500
			}
			return s.Journal.ListDeadLetterItems(ctx, a.Limit, a.Offset)
		},
	}

	s.tools["reactor_list_notification_channels"] = toolDef{
		tool: Tool{
			Name:        "reactor_list_notification_channels",
			Description: "List configured notification channels (id, name, kind, created_at). Channel config_json is intentionally NOT returned because it can hold secrets.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			channels, err := s.Journal.ListNotificationChannels(ctx)
			if err != nil {
				return nil, err
			}
			// Redact config_json (SMTP password, webhook auth header) so a
			// secret can't leak through the MCP surface.
			out := make([]map[string]any, 0, len(channels))
			for _, c := range channels {
				out = append(out, map[string]any{
					"id":         c.ID,
					"name":       c.Name,
					"kind":       c.Kind,
					"created_at": c.CreatedAt,
				})
			}
			return out, nil
		},
	}

	if s.Dispatch != nil {
		s.tools["reactor_register_workflow"] = toolDef{
			tool: Tool{
				Name:        "reactor_register_workflow",
				Description: "Register metadata only (non-executable). Existing slugs return their current id. Use reactor_create_workflow to compile, publish an immutable artifact, and append an executable version; or use the CLI workflow build + register pair. Returns the workflow id. Requires --allow-write.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"slug"},
					"properties": map[string]any{
						"slug":        map[string]any{"type": "string"},
						"sdk_version": map[string]any{"type": "string"},
						"code_hash":   map[string]any{"type": "string"},
						"dag":         map[string]any{"type": "object"},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					Slug       string          `json:"slug"`
					SDKVersion string          `json:"sdk_version"`
					CodeHash   string          `json:"code_hash"`
					DAG        json.RawMessage `json:"dag"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.Slug == "" {
					return nil, fmt.Errorf("%w: slug required", errInvalidParamsErr)
				}
				if !codegen.IsValidSlug(a.Slug) {
					return nil, fmt.Errorf("%w: slug %q must match ^[a-z][a-z0-9-]*$ (becomes a filesystem path)", errInvalidParamsErr, a.Slug)
				}
				if a.SDKVersion == "" {
					a.SDKVersion = "0.1.0"
				}
				if len(a.DAG) == 0 {
					a.DAG = json.RawMessage(`{}`)
				}
				// The existence check must ask about the SAME tenant the create
				// below writes to, which is DefaultTenant (CreateWorkflow is the
				// unscoped entry point). Asking unscoped is the SkipIfExists bug:
				// slugs are unique per tenant, so another tenant owning this slug
				// made this return created:false with THEIR workflow id while
				// nothing existed in the tenant the caller was writing to.
				existing, err := s.Journal.WorkflowIDBySlugInTenant(ctx, a.Slug, journal.DefaultTenant)
				if err == nil && existing != "" {
					return map[string]any{"id": existing, "slug": a.Slug, "created": false}, nil
				}
				if err != nil && !errors.Is(err, journal.ErrNotFound) {
					return nil, err
				}
				id, err := newMCPWorkflowID()
				if err != nil {
					return nil, err
				}
				if err := s.Journal.CreateWorkflow(ctx, id, a.Slug, a.CodeHash, a.SDKVersion, a.DAG); err != nil {
					return nil, err
				}
				return map[string]any{"id": id, "slug": a.Slug, "created": true}, nil
			},
		}

		if s.StateRoot != "" {
			s.tools["reactor_create_workflow"] = toolDef{
				tool: Tool{
					Name:        "reactor_create_workflow",
					Description: "Author a workflow: compile + register it from Go source you supply. Pass main_go (the workflow's main.go, importing github.com/bright-interaction/reactor) and an optional dag. The daemon builds it in-process with NO external API key: it runs the import allowlist (stdlib + the Reactor SDK only) + lint + `go build`, registers the workflows row, and returns the workflow id, ready for reactor_grant_secret + reactor_dispatch_workflow. This is the MCP authoring path: the AI client writes the code, Reactor builds it. Requires --allow-write.",
					InputSchema: map[string]any{
						"type":     "object",
						"required": []string{"slug", "main_go"},
						"properties": map[string]any{
							"slug":        map[string]any{"type": "string", "description": "filesystem-safe id matching ^[a-z][a-z0-9-]*$"},
							"main_go":     map[string]any{"type": "string", "description": "the workflow's complete main.go source"},
							"dag":         map[string]any{"type": "object", "description": "optional dag.json describing the step graph"},
							"sdk_version": map[string]any{"type": "string"},
						},
					},
				},
				handler: func(ctx context.Context, args json.RawMessage) (any, error) {
					var a struct {
						Slug       string          `json:"slug"`
						MainGo     string          `json:"main_go"`
						DAG        json.RawMessage `json:"dag"`
						SDKVersion string          `json:"sdk_version"`
					}
					if err := json.Unmarshal(args, &a); err != nil {
						return nil, fmt.Errorf("%w: %v", errInvalidParamsErr, err)
					}
					if a.Slug == "" || strings.TrimSpace(a.MainGo) == "" {
						return nil, fmt.Errorf("%w: slug and main_go are required", errInvalidParamsErr)
					}
					res, err := codegen.BuildAndRegisterSource(ctx, s.Journal, codegen.BuildSourceRequest{
						Slug:       a.Slug,
						MainGo:     a.MainGo,
						DAGJSON:    string(a.DAG),
						StateRoot:  s.StateRoot,
						SDKVersion: a.SDKVersion,
						// Existing slugs append a new immutable artifact-bound version;
						// they are not duplicate workflow rows.
						SkipIfExists: true,
					})
					if err != nil {
						return nil, err
					}
					return map[string]any{"id": res.WorkflowID, "slug": a.Slug, "binary_path": res.BinaryPath, "built": true}, nil
				},
			}
		}

		s.tools["reactor_grant_secret"] = toolDef{
			tool: Tool{
				Name:        "reactor_grant_secret",
				Description: "Grant a workflow read-access to a credential by id. Idempotent. Requires --allow-write.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"workflow_id", "credential_id"},
					"properties": map[string]any{
						"workflow_id":   map[string]any{"type": "string"},
						"credential_id": map[string]any{"type": "string"},
						"note":          map[string]any{"type": "string"},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					WorkflowID   string `json:"workflow_id"`
					CredentialID string `json:"credential_id"`
					Note         string `json:"note"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.WorkflowID == "" || a.CredentialID == "" {
					return nil, fmt.Errorf("%w: workflow_id and credential_id required", errInvalidParamsErr)
				}
				if err := s.Journal.GrantSecret(ctx, a.WorkflowID, a.CredentialID, "mcp", a.Note); err != nil {
					return nil, err
				}
				return map[string]any{"workflow_id": a.WorkflowID, "credential_id": a.CredentialID, "ok": true}, nil
			},
		}

		s.tools["reactor_revoke_secret"] = toolDef{
			tool: Tool{
				Name:        "reactor_revoke_secret",
				Description: "Revoke a workflow's grant on a credential. Errors if no grant exists. Requires --allow-write.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"workflow_id", "credential_id"},
					"properties": map[string]any{
						"workflow_id":   map[string]any{"type": "string"},
						"credential_id": map[string]any{"type": "string"},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					WorkflowID   string `json:"workflow_id"`
					CredentialID string `json:"credential_id"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.WorkflowID == "" || a.CredentialID == "" {
					return nil, fmt.Errorf("%w: workflow_id and credential_id required", errInvalidParamsErr)
				}
				if err := s.Journal.RevokeSecret(ctx, a.WorkflowID, a.CredentialID); err != nil {
					return nil, err
				}
				return map[string]any{"workflow_id": a.WorkflowID, "credential_id": a.CredentialID, "revoked": true}, nil
			},
		}

		s.tools["reactor_dispatch_workflow"] = toolDef{
			tool: Tool{
				Name:        "reactor_dispatch_workflow",
				Description: "Trigger a workflow run with an operator-supplied JSON payload. Returns the new run_id. Requires --allow-write at server start.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"slug"},
					"properties": map[string]any{
						"slug":    map[string]any{"type": "string"},
						"payload": map[string]any{"type": "object"},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					Slug    string          `json:"slug"`
					Payload json.RawMessage `json:"payload"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.Slug == "" {
					return nil, fmt.Errorf("%w: slug required", errInvalidParamsErr)
				}
				if len(a.Payload) == 0 {
					a.Payload = json.RawMessage(`{}`)
				}
				runID, err := s.Dispatch(ctx, a.Slug, a.Payload)
				if err != nil {
					return nil, err
				}
				return map[string]any{"run_id": runID}, nil
			},
		}

		s.tools["reactor_cancel_run"] = toolDef{
			tool: Tool{
				Name:        "reactor_cancel_run",
				Description: "Stop a run. A suspended run is cancelled immediately; a running run is flagged and the daemon kills it within ~2s. Returns the outcome (cancelled | requested | not_cancellable). Requires --allow-write.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"run_id"},
					"properties": map[string]any{
						"run_id": map[string]any{"type": "string"},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					RunID string `json:"run_id"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.RunID == "" {
					return nil, fmt.Errorf("%w: run_id required", errInvalidParamsErr)
				}
				outcome, err := s.Journal.RequestRunCancel(ctx, a.RunID)
				if err != nil {
					return nil, err
				}
				return map[string]any{"run_id": a.RunID, "outcome": outcome}, nil
			},
		}
	}

	// Knowledge corpus reads. Always registered (read-only).
	if s.Knowledge != nil {
		s.tools["reactor_search_knowledge"] = toolDef{
			tool: Tool{
				Name:        "reactor_search_knowledge",
				Description: "BM25 search across the knowledge corpus. Returns top-N entries with id, topic, title, and a body excerpt. Use before generating workflow code so prior lessons are honoured.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"query"},
					"properties": map[string]any{
						"query": map[string]any{"type": "string"},
						"limit": map[string]any{"type": "integer", "default": 5},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					Query string `json:"query"`
					Limit int    `json:"limit"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.Query == "" {
					return nil, fmt.Errorf("%w: query required", errInvalidParamsErr)
				}
				if a.Limit == 0 {
					a.Limit = 5
				}
				hits, err := s.Knowledge.Search(ctx, a.Query, a.Limit)
				if err != nil {
					return nil, err
				}
				out := make([]map[string]any, 0, len(hits))
				for _, h := range hits {
					out = append(out, map[string]any{
						"id":             h.Entry.Frontmatter.ID,
						"topic":          h.Entry.Frontmatter.Topic,
						"title":          h.Entry.Frontmatter.Title,
						"score":          h.Score,
						"gold":           h.Entry.Frontmatter.Gold,
						"citation_count": h.Entry.Frontmatter.CitationCount,
						"body":           h.Entry.Body,
					})
				}
				return map[string]any{"hits": out}, nil
			},
		}
	}

	// Graph queries. Always registered (read-only).
	if s.Graph != nil {
		s.tools["reactor_query_graph"] = toolDef{
			tool: Tool{
				Name:        "reactor_query_graph",
				Description: "Query the runtime graph (workflows, credentials, triggers, recent runs, knowledge) by free-text. Returns a subgraph in one call instead of forcing 5+ list/get roundtrips.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"query"},
					"properties": map[string]any{
						"query": map[string]any{"type": "string"},
						"limit": map[string]any{"type": "integer", "default": 10},
					},
				},
			},
			handler: func(_ context.Context, args json.RawMessage) (any, error) {
				var a struct {
					Query string `json:"query"`
					Limit int    `json:"limit"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.Query == "" {
					return nil, fmt.Errorf("%w: query required", errInvalidParamsErr)
				}
				if a.Limit == 0 {
					a.Limit = 10
				}
				return s.Graph.Query(a.Query, a.Limit), nil
			},
		}

		s.tools["reactor_get_neighbors"] = toolDef{
			tool: Tool{
				Name:        "reactor_get_neighbors",
				Description: "Walk the graph from node_id outward by depth steps. Optional edge_kinds filter (USES, FIRES, BELONGS_TO, FROM, DERIVED_FROM, CITED_BY, SUPERSEDES).",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"node_id"},
					"properties": map[string]any{
						"node_id":    map[string]any{"type": "string"},
						"depth":      map[string]any{"type": "integer", "default": 1},
						"edge_kinds": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					},
				},
			},
			handler: func(_ context.Context, args json.RawMessage) (any, error) {
				var a struct {
					NodeID    string   `json:"node_id"`
					Depth     int      `json:"depth"`
					EdgeKinds []string `json:"edge_kinds"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.NodeID == "" {
					return nil, fmt.Errorf("%w: node_id required", errInvalidParamsErr)
				}
				if a.Depth == 0 {
					a.Depth = 1
				}
				return s.Graph.Neighbors(a.NodeID, a.Depth, a.EdgeKinds...), nil
			},
		}
	}

	// Knowledge writes + post-mortem. Gated behind --allow-write
	// (Dispatch != nil is the proxy for write mode in the existing
	// design; we mirror that gate to keep the surface predictable).
	if s.Knowledge != nil && s.Dispatch != nil {
		s.tools["reactor_add_knowledge"] = toolDef{
			tool: Tool{
				Name:        "reactor_add_knowledge",
				Description: "Append a new entry to the knowledge corpus. Body is scanned for PII / secrets and rejected on hit. Requires --allow-write.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"topic", "title", "body"},
					"properties": map[string]any{
						"topic":   map[string]any{"type": "string"},
						"title":   map[string]any{"type": "string"},
						"body":    map[string]any{"type": "string"},
						"sources": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"tags":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					Topic   string   `json:"topic"`
					Title   string   `json:"title"`
					Body    string   `json:"body"`
					Sources []string `json:"sources"`
					Tags    []string `json:"tags"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.Topic == "" || a.Title == "" || a.Body == "" {
					return nil, fmt.Errorf("%w: topic, title, body required", errInvalidParamsErr)
				}
				e, err := s.Knowledge.Add(ctx, knowledge.Entry{
					Frontmatter: knowledge.Frontmatter{
						Topic:     a.Topic,
						Title:     a.Title,
						Sources:   a.Sources,
						Tags:      a.Tags,
						CreatedBy: "claude",
					},
					Body: a.Body,
				})
				if err != nil {
					return nil, err
				}
				return map[string]any{"id": e.Frontmatter.ID, "topic": e.Frontmatter.Topic, "added": true}, nil
			},
		}

		s.tools["reactor_revise_knowledge"] = toolDef{
			tool: Tool{
				Name:        "reactor_revise_knowledge",
				Description: "Supersede an existing knowledge entry with new body. Old entry stays on disk; supersedes chain links them. Requires --allow-write.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"id", "new_body", "reason"},
					"properties": map[string]any{
						"id":       map[string]any{"type": "string"},
						"new_body": map[string]any{"type": "string"},
						"reason":   map[string]any{"type": "string"},
					},
				},
			},
			handler: func(ctx context.Context, args json.RawMessage) (any, error) {
				var a struct {
					ID      string `json:"id"`
					NewBody string `json:"new_body"`
					Reason  string `json:"reason"`
				}
				if err := json.Unmarshal(args, &a); err != nil || a.ID == "" || a.NewBody == "" || a.Reason == "" {
					return nil, fmt.Errorf("%w: id, new_body, reason required", errInvalidParamsErr)
				}
				revised, err := s.Knowledge.Supersede(ctx, a.ID, knowledge.Entry{
					Frontmatter: knowledge.Frontmatter{CreatedBy: "claude"},
					Body:        a.NewBody,
				}, a.Reason)
				if err != nil {
					return nil, err
				}
				return map[string]any{"new_id": revised.Frontmatter.ID, "supersedes": []string{a.ID}}, nil
			},
		}

		if s.PostMortem != nil {
			s.tools["reactor_record_postmortem"] = toolDef{
				tool: Tool{
					Name:        "reactor_record_postmortem",
					Description: "Generate a post-mortem knowledge entry from a failed run's journal. Available only when AI post-mortem egress is explicitly enabled; can backfill an old run. Requires --allow-write.",
					InputSchema: map[string]any{
						"type":     "object",
						"required": []string{"run_id"},
						"properties": map[string]any{
							"run_id": map[string]any{"type": "string"},
						},
					},
				},
				handler: func(ctx context.Context, args json.RawMessage) (any, error) {
					var a struct {
						RunID string `json:"run_id"`
					}
					if err := json.Unmarshal(args, &a); err != nil || a.RunID == "" {
						return nil, fmt.Errorf("%w: run_id required", errInvalidParamsErr)
					}
					id, err := s.PostMortem(ctx, a.RunID)
					if err != nil {
						return nil, err
					}
					return map[string]any{"entry_id": id, "run_id": a.RunID}, nil
				},
			}
		}
	}
}

// newMCPWorkflowID mirrors the cmd/reactor helper: "wf_" + 16 hex
// chars (8 bytes from crypto/rand). Inlined here so the MCP package
// doesn't depend on cmd/reactor.
func newMCPWorkflowID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mcp: workflow id: %w", err)
	}
	return "wf_" + hex.EncodeToString(b), nil
}
