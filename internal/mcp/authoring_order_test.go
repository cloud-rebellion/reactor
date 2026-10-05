package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestHTTPMCPAuthoringRejectsImpossibleVisualDependencyBeforePublication(t *testing.T) {
	reactorRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REACTOR_SDK_REPLACE", reactorRoot)
	srv, store, _ := newTestServer(t, true)
	srv.StateRoot = t.TempDir()
	const slug = "reversed-dependency"
	source := `package main
import (
  "context"
  reactor "github.com/bright-interaction/reactor/sdk"
  "github.com/bright-interaction/reactor/sdk/runtime"
)
func run(ctx context.Context, flow reactor.Flow, _ struct{}) error {
  _, err := reactor.Step(flow, ctx, "send", reactor.StepOpts{}, func(context.Context) (string, error) { return "sent", nil })
  if err != nil { return err }
  _, err = reactor.Step(flow, ctx, "fetch", reactor.StepOpts{}, func(context.Context) (string, error) { return "fetched", nil })
  return err
}
func main() { runtime.Serve(reactor.Workflow{Slug: "reversed-dependency", Version: "0.1.0"}, reactor.EventTrigger{}, run) }
`
	args := map[string]any{
		"slug": slug, "main_go": source,
		"dag": map[string]any{
			"steps": []any{
				map[string]any{"name": "send", "kind": "step", "depends_on": []string{"fetch"}},
				map[string]any{"name": "fetch", "kind": "step"},
			},
		},
	}
	for _, name := range []string{"reactor_validate_workflow", "reactor_create_workflow"} {
		body, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		out := httptest.NewRecorder()
		srv.ServeHTTP(out, req)
		if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"isError":true`) || !strings.Contains(out.Body.String(), "dependency order mismatch") {
			t.Fatalf("%s accepted misleading visual dependency: HTTP %d %s", name, out.Code, out.Body.String())
		}
		if _, err := store.WorkflowIDBySlugInTenant(context.Background(), slug, journal.DefaultTenant); !errors.Is(err, journal.ErrNotFound) {
			t.Fatalf("%s persisted rejected workflow: %v", name, err)
		}
	}
}
