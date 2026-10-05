package mcp

import (
	"io/fs"
	"strings"
	"testing"

	reactordocs "github.com/bright-interaction/reactor/docs"
	"github.com/bright-interaction/reactor/internal/graph"
	"github.com/bright-interaction/reactor/internal/knowledge"
)

// TestReadToolSchemasAdvertisePaginationDefaultsAndBounds keeps tools/list
// useful to clients that construct requests from the advertised JSON Schema.
// These values are the handlers' effective defaults and validation limits;
// drift here otherwise turns an otherwise valid generated request into an
// avoidable invalid-params response.
func TestReadToolSchemasAdvertisePaginationDefaultsAndBounds(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, false)
	var err error
	srv.Knowledge, err = knowledge.New(t.TempDir())
	if err != nil {
		t.Fatalf("knowledge store: %v", err)
	}
	srv.Graph = graph.New()
	srv.registerTools()

	assertProperty := func(toolName, property string, want map[string]any) {
		t.Helper()
		definition, ok := srv.tools[toolName]
		if !ok {
			t.Fatalf("tool %q is not registered", toolName)
		}
		properties, ok := definition.tool.InputSchema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("tool %q has no properties schema", toolName)
		}
		actual, ok := properties[property].(map[string]any)
		if !ok {
			t.Fatalf("tool %q property %q has no schema", toolName, property)
		}
		for key, expected := range want {
			if actual[key] != expected {
				t.Errorf("tool %q property %q %s = %#v, want %#v", toolName, property, key, actual[key], expected)
			}
		}
	}

	assertProperty("reactor_list_runs", "limit", map[string]any{"minimum": 1, "maximum": 500, "default": 50})
	assertProperty("reactor_list_runs", "offset", map[string]any{"minimum": 0, "maximum": 10000, "default": 0})
	assertProperty("reactor_get_credential_audit", "limit", map[string]any{"minimum": 1, "maximum": 500, "default": 50})
	assertProperty("reactor_list_dead_letters", "limit", map[string]any{"minimum": 1, "maximum": 500, "default": 50})
	assertProperty("reactor_list_dead_letters", "offset", map[string]any{"minimum": 0, "maximum": 10000, "default": 0})
	assertProperty("reactor_search_knowledge", "limit", map[string]any{"minimum": 1, "maximum": 100, "default": 5})
	assertProperty("reactor_query_graph", "limit", map[string]any{"minimum": 1, "maximum": 100, "default": 10})
	assertProperty("reactor_get_neighbors", "depth", map[string]any{"minimum": 1, "maximum": 8, "default": 1})
	assertProperty("reactor_get_neighbors", "edge_kinds", map[string]any{"maxItems": 32})
}

// Command trigger tools are the unattended half of the AI authoring contract.
// Keep their embedded MCP documentation discoverable as a complete set: an
// agent that reads the docs must be able to find the list/create/update/state/
// delete lifecycle for schedules, webhooks, and terminal chains. This catches
// documentation drift when a new trigger surface is registered in code.
func TestCommandTriggerLifecycleToolsAreDocumented(t *testing.T) {
	t.Parallel()
	raw, err := fs.ReadFile(reactordocs.FS, "mcp.md")
	if err != nil {
		t.Fatalf("read embedded MCP documentation: %v", err)
	}
	doc := string(raw)
	for _, name := range []string{
		"reactor_list_command_automation_schedules",
		"reactor_create_command_automation_schedule",
		"reactor_update_command_automation_schedule",
		"reactor_set_command_automation_schedule_state",
		"reactor_delete_command_automation_schedule",
		"reactor_list_command_automation_webhooks",
		"reactor_create_command_automation_webhook",
		"reactor_update_command_automation_webhook",
		"reactor_set_command_automation_webhook_state",
		"reactor_delete_command_automation_webhook",
		"reactor_list_command_automation_chains",
		"reactor_create_command_automation_chain",
		"reactor_update_command_automation_chain",
		"reactor_set_command_automation_chain_state",
		"reactor_delete_command_automation_chain",
	} {
		if !strings.Contains(doc, "`"+name+"`") {
			t.Errorf("embedded MCP documentation does not mention %s", name)
		}
	}
}
