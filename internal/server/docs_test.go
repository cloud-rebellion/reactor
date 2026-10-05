package server

import (
	"io"
	"io/fs"
	"net/http"
	"strings"
	"testing"

	docsfs "github.com/bright-interaction/reactor/docs"
)

func TestDocsIndexRendersEveryDoc(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t)
	body := getBody(t, srv.URL+"/docs")
	s := string(body)
	for _, want := range []string{
		"Documentation",
		"Dashboard pages + endpoints",
		"REST API reference",
		"MCP server + tool reference",
		"Notifications (Slack + webhook + email)",
		"Workflow chaining",
		"Teams, users, sessions, API tokens",
		"Architecture",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("docs index missing %q", want)
		}
	}
}

func TestDocsPageRendersMarkdownAsHTML(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t)
	body := getBody(t, srv.URL+"/docs/dashboard")
	s := string(body)
	for _, want := range []string{
		"<h1",                         // headings rendered
		"<table",                      // GFM tables rendered
		"<code",                       // inline code rendered
		"Dashboard pages + endpoints", // doc title in the heading slot
		"docs-shell",                  // nav + body shell present
		"docs-nav",
		`href="/docs/api"`, // left-rail link to another page
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("doc page missing %q\n--- snip ---\n%s", want, s[:min(len(s), 2000)])
		}
	}
}

func TestDocsAPIReferencesDedicatedCommandWebhookIngress(t *testing.T) {
	t.Parallel()
	raw, err := fs.ReadFile(docsfs.FS, "api.md")
	if err != nil {
		t.Fatalf("read embedded REST API docs: %v", err)
	}
	body, err := renderMarkdown(raw)
	if err != nil {
		t.Fatalf("render embedded REST API docs: %v", err)
	}
	s := body
	for _, want := range []string{
		"/command-webhook/{token_id}",
		"dedicated command-automation HMAC binding",
		"request bodies never enter the command",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("REST API docs missing %q", want)
		}
	}
}

func TestDocsPageUnknownSlug404(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/docs/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 404\n%s", resp.StatusCode, body)
	}
}

func TestDocsPageTraversalRejected(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t)
	// isValidDocSlug rejects any char outside a-z0-9-_; chi's URL
	// pattern also blocks /, but the handler's own check rejects e.g.
	// "../something" if it ever reached us.
	for _, bad := range []string{"with space", "../escape", "with.dot"} {
		resp, err := http.Get(srv.URL + "/docs/" + bad)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("slug %q should not have resolved to 200", bad)
		}
	}
}

func TestDocsRoutePublicWithoutAuth(t *testing.T) {
	t.Parallel()
	// Docs must be readable on the login page too, so the auth
	// middleware exempts /docs/* (verified via newTestServer which
	// constructs Server with AllowNoAuth=true; the more important
	// check is that the public-route helper includes /docs).
	if !isSessionAuthExempt("/docs") {
		t.Fatal("/docs should be session-auth exempt")
	}
	if !isSessionAuthExempt("/docs/dashboard") {
		t.Fatal("/docs/* should be session-auth exempt (sub-page)")
	}
}
