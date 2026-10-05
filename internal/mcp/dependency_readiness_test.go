package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	_ "modernc.org/sqlite"
)

func credentialStepSource(slug, credentialExpr string) ([]byte, json.RawMessage) {
	source, dag := visualStepFixture(slug, "execute")
	main := strings.Replace(string(source), `runtime "github.com/bright-interaction/reactor/sdk/runtime"`,
		`runtime "github.com/bright-interaction/reactor/sdk/runtime"
    vault "github.com/bright-interaction/reactor/sdk/vault"`, 1)
	main = strings.Replace(main, `return "ok", nil`, `_ = vault.MustGet(`+credentialExpr+`); return "ok", nil`, 1)
	return []byte(main), dag
}

func TestMCPDependencyReadinessTracksGrantAndRevoke(t *testing.T) {
	ctx := context.Background()
	s, j, credentialsRepo := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	const slug = "needs-stripe-key"
	const workflowID = "wf_needs_stripe_key"
	source, dag := credentialStepSource(slug, `"stripe-key"`)
	artifact := publishVerifiedTestArtifact(t, s, slug, []byte("compiled-workflow"), source, dag)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, workflowID, slug, sourceCodeHashForTest(source),
		"0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	if err := credentialsRepo.Create(ctx, credentials.CreateParams{ID: "stripe-key", Name: "Stripe key"}); err != nil {
		t.Fatal(err)
	}
	check := func(wantMissing, wantReady bool) {
		t.Helper()
		review := callOperationalTool(t, s, "reactor_review_workflow", map[string]any{"slug": slug}, false)
		preflight := callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": slug}, false)
		var reviewView, preflightView map[string]any
		if err := json.Unmarshal(review, &reviewView); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(preflight, &preflightView); err != nil {
			t.Fatal(err)
		}
		for _, receipt := range []map[string]any{reviewView, preflightView} {
			deps, ok := receipt["dependencies"].(map[string]any)
			if !ok {
				t.Fatalf("missing dependency receipt: %v", receipt)
			}
			missing, ok := deps["missing_grants"].([]any)
			if !ok {
				t.Fatalf("missing grants are not an array: %v", deps)
			}
			if (len(missing) > 0) != wantMissing {
				t.Fatalf("missing grants = %v, want missing %v", missing, wantMissing)
			}
			if wantMissing && (len(missing) != 1 || missing[0] != "stripe-key") {
				t.Fatalf("wrong missing grant: %v", missing)
			}
			if strings.Contains(string(review), "grant-note-secret-sentinel") || strings.Contains(string(preflight), "grant-note-secret-sentinel") {
				t.Fatal("grant note leaked into review or preflight")
			}
		}
		if preflightView["dispatchable_now"] != wantReady {
			t.Fatalf("dispatchable_now = %v, want %v: %s", preflightView["dispatchable_now"], wantReady, preflight)
		}
		if wantMissing && reviewView["review_status"] != "needs_connections" {
			t.Fatalf("review did not flag missing connection: %s", review)
		}
	}
	check(true, false)
	blocked := callOperationalTool(t, s, "reactor_dispatch_workflow", map[string]any{"slug": slug}, true)
	if !strings.Contains(string(blocked), "credential grant or connection is missing") {
		t.Fatalf("MCP dispatch did not honor readiness: %s", blocked)
	}
	if err := j.GrantSecret(ctx, workflowID, "stripe-key", "test", "grant-note-secret-sentinel"); err != nil {
		t.Fatal(err)
	}
	check(false, true)
	if err := j.RevokeSecret(ctx, workflowID, "stripe-key"); err != nil {
		t.Fatal(err)
	}
	check(true, false)
}

func TestMCPDependencyReadinessChecksTenantAndOAuthConnectionState(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "oauth-readiness.db")
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	j := journal.New(db, journal.EngineSQLite)
	s := &Server{
		Journal: j, Credentials: credentials.New(db, credentials.EngineSQLite),
		OAuth:     oauth.New(db, oauth.EngineSQLite, []byte(strings.Repeat("k", 32))),
		StateRoot: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dispatch: func(context.Context, string, json.RawMessage) (string, error) { return "run_test", nil },
	}
	if err := s.OAuth.UpsertProvider(ctx, oauth.Provider{ProviderID: "google", Name: "Google",
		AuthURL: "https://accounts.example/auth", TokenURL: "https://accounts.example/token", Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, status, token_access_mode, legacy_raw_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "conn_mail", journal.DefaultTenant, "google", "mail",
		[]byte("oauth-token-secret-sentinel"), "disconnected", "legacy_raw", "grandfathered"); err != nil {
		t.Fatal(err)
	}
	const slug, workflowID = "connected-mail-readiness", "wf_connected_mail_readiness"
	source, dag := credentialStepSource(slug, `"oauth:conn_mail"`)
	artifact := publishVerifiedTestArtifact(t, s, slug, []byte("compiled-workflow"), source, dag)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, workflowID, slug, sourceCodeHashForTest(source),
		"0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	if err := j.GrantSecret(ctx, workflowID, "oauth:conn_mail", "test", ""); err != nil {
		t.Fatal(err)
	}
	preflight := callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": slug}, false)
	if !strings.Contains(string(preflight), `"inactive_connections":["oauth:conn_mail"]`) ||
		!strings.Contains(string(preflight), `"dispatchable_now":false`) {
		t.Fatalf("disconnected OAuth account passed readiness: %s", preflight)
	}
	if strings.Contains(string(preflight), "oauth-token-secret-sentinel") {
		t.Fatal("OAuth ciphertext leaked")
	}
	if _, err := db.ExecContext(ctx, `UPDATE oauth_connections SET status='connected' WHERE id=?`, "conn_mail"); err != nil {
		t.Fatal(err)
	}
	preflight = callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": slug}, false)
	if !strings.Contains(string(preflight), `"inactive_connections":[]`) ||
		!strings.Contains(string(preflight), `"dispatchable_now":true`) {
		t.Fatalf("connected, granted account remained blocked: %s", preflight)
	}
	if _, err := db.ExecContext(ctx, `UPDATE oauth_connections SET tenant_id=? WHERE id=?`, "other-tenant", "conn_mail"); err != nil {
		t.Fatal(err)
	}
	preflight = callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": slug}, false)
	if !strings.Contains(string(preflight), `"unresolved_reference_count":1`) ||
		!strings.Contains(string(preflight), `"dispatchable_now":false`) || strings.Contains(string(preflight), "other-tenant") ||
		strings.Contains(string(preflight), "oauth:conn_mail") {
		t.Fatalf("cross-tenant account passed or leaked tenant metadata: %s", preflight)
	}
}

func TestMCPDependencyReadinessLabelsRuntimeComputedReference(t *testing.T) {
	ctx := context.Background()
	s, j, _ := newTestServer(t, true)
	s.StateRoot = t.TempDir()
	const slug = "dynamic-credential"
	source, dag := credentialStepSource(slug, "credentialID")
	source = []byte(strings.Replace(string(source), `_ = vault.MustGet(credentialID)`,
		`credentialID := "stripe-key"; _ = vault.MustGet(credentialID)`, 1))
	artifact := publishVerifiedTestArtifact(t, s, slug, []byte("compiled-workflow"), source, dag)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_dynamic_credential", slug, sourceCodeHashForTest(source),
		"0.1.0", artifact.Digest, dag, journal.DefaultTenant, sourceManifestPinForTest(t, artifact)); err != nil {
		t.Fatal(err)
	}
	preflight := callOperationalTool(t, s, "reactor_preflight_dispatch_workflow", map[string]any{"slug": slug}, false)
	if !strings.Contains(string(preflight), `"status":"partial"`) ||
		!strings.Contains(string(preflight), `"dynamic_call_count":1`) ||
		strings.Contains(string(preflight), `"required_credential_ids":["stripe-key"]`) {
		t.Fatalf("runtime-computed credential was presented as proven: %s", preflight)
	}
}

func TestMCPDependencyParserReportsOnlyDirectLiteralSDKReferences(t *testing.T) {
	const source = `package main
import (
 v "github.com/bright-interaction/reactor/sdk/vault"
 api "github.com/bright-interaction/reactor/sdk/http"
 mail "github.com/bright-interaction/reactor/sdk/email"
)
func run() {
 _ = v.MustGet("stripe-key")
 _ = v.Get(nil, "other-key")
 _ = api.ConnectorGet(nil, "oauth:crm", "/v1", nil)
 _ = mail.SendConnected(nil, "oauth:mail", message)
 _ = mail.SendConnected(nil, "oauth:"+connectionID, message)
 _ = v.MustGet(computedID)
}`
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	refs := make(map[string]struct{})
	var result dependencyReadiness
	collectLiteralSDKRefs(file, refs, &result)
	for _, id := range []string{"stripe-key", "other-key", "oauth:crm", "oauth:mail"} {
		if _, ok := refs[id]; !ok {
			t.Fatalf("literal %q not found: %#v", id, refs)
		}
	}
	if len(refs) != 4 || result.dynamicCalls != 2 {
		t.Fatalf("refs=%#v dynamic=%d; expected four literal refs and two unknown expressions", refs, result.dynamicCalls)
	}
}

func TestMCPDependencyParserBoundsReferenceInventory(t *testing.T) {
	var source strings.Builder
	source.WriteString("package main\nimport v \"github.com/bright-interaction/reactor/sdk/vault\"\nfunc run() {\n")
	for i := 0; i < maxMCPDependencyRefs+10; i++ {
		fmt.Fprintf(&source, "_ = v.MustGet(\"credential-%03d\")\n", i)
	}
	source.WriteString("}\n")
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", source.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	refs := make(map[string]struct{})
	var result dependencyReadiness
	collectLiteralSDKRefs(file, refs, &result)
	if len(refs) != maxMCPDependencyRefs || !result.truncated {
		t.Fatalf("bounded refs=%d truncated=%t", len(refs), result.truncated)
	}
}
