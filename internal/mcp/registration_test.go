package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

// Serve and ServeHTTP share one Server type. Registration must therefore be
// idempotent across transports: rebuilding the map in the stdio path could
// race with HTTP requests and discard handlers added by an embedding.
func TestServeDoesNotRebuildRegisteredToolMap(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	srv.ensureRegistered()
	srv.tools["reactor_test_embedded"] = toolDef{
		tool: Tool{
			Name:        "reactor_test_embedded",
			Description: "test-only embedded tool",
			InputSchema: map[string]any{"type": "object"},
		},
		handler: func(context.Context, json.RawMessage) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	}

	var out bytes.Buffer
	if err := srv.Serve(context.Background(), bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if _, ok := srv.tools["reactor_test_embedded"]; !ok {
		t.Fatal("Serve rebuilt the tool map and discarded an embedded handler")
	}
}
