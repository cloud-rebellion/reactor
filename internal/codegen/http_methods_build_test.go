package codegen

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The authoring gate forbids net/http imports. Compile the supported helper
// surface through the same offline build path used by MCP workflow creation.
func TestBuildAndRegisterSourceAcceptsSDKHTTPMutationsWithoutNetHTTP(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REACTOR_SDK_REPLACE", repoRoot)
	const source = `package main

import (
    "context"
    ahttp "github.com/bright-interaction/reactor/sdk/http"
)

func compiledHTTPMethods(ctx context.Context, c *ahttp.Client) {
    _ = c.PostJSON(ctx, "https://api.example.test/items", map[string]int{"x": 1}, nil)
    _ = c.PutJSON(ctx, "https://api.example.test/items/1", map[string]int{"x": 1}, nil)
    _ = c.Put(ctx, "https://api.example.test/items/1/published", nil)
    _ = c.PatchJSON(ctx, "https://api.example.test/items/1", map[string]int{"x": 2}, nil)
    _ = c.Delete(ctx, "https://api.example.test/items/1", nil)
}

func main() {}
`
	root := t.TempDir()
	res, err := BuildAndRegisterSource(context.Background(), &fakeJournal{}, BuildSourceRequest{
		Slug: "sdk-http-mutations", MainGo: source, DAGJSON: `{"steps":[]}`, StateRoot: root,
	})
	if err != nil {
		t.Fatalf("authoring build rejected supported HTTP methods: %v", err)
	}
	if _, err := os.Stat(res.BinaryPath); err != nil {
		t.Fatalf("authoring build did not retain compiled artifact: %v", err)
	}
}
