package main

import (
	"strings"
	"testing"
)

func TestArtifactPublicationScopesAreIndependent(t *testing.T) {
	t.Setenv("REACTOR_MCP_ALLOW_ARTIFACT_PUBLICATION", "")
	t.Setenv("REACTOR_MCP_ALLOW_AUTHORING", "")
	t.Setenv("REACTOR_MCP_ALLOW_DISPATCH", "")
	base := []string{
		"--db", "sqlite://reactor.db", "--root", t.TempDir(),
		"--master-key", strings.Repeat("a", 64), "--addr", "127.0.0.1:7777",
	}
	readOnly, err := parseServeFlags(base)
	if err != nil {
		t.Fatal(err)
	}
	if readOnly.mcpArtifactPublication {
		t.Fatal("artifact publication unexpectedly enabled by default")
	}
	allowed, err := parseServeFlags(append(append([]string{}, base...), "--mcp-allow-artifact-publication"))
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.mcpArtifactPublication || allowed.mcpAuthoring || allowed.mcpDispatch {
		t.Fatalf("artifact publication flag opened unrelated capabilities: %+v", allowed)
	}
	stdio := mcpStdioWriteScopes(false, false, false, false, false, false, false, false, false, false, true)
	if !stdio.ArtifactPublication || stdio.Authoring || stdio.Dispatch {
		t.Fatalf("stdio publication scope opened unrelated capabilities: %+v", stdio)
	}
}
