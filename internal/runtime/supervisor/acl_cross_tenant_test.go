package supervisor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

// TestSecretFetchDoesNotResolveWorkflowAcrossTenants is a cross-tenant secret
// disclosure.
//
// The secret ACL gate resolved the calling workflow with the UNSCOPED
// WorkflowIDBySlug, whose query is `WHERE slug = $1 ORDER BY created_at DESC
// LIMIT 1`. Slugs are unique PER TENANT, so when two tenants own the same slug
// that returns whichever tenant registered it most recently, regardless of who
// is actually running. HasGrant is then asked about the WRONG workflow, and a
// grant belonging to the victim authorises the attacker's run. Vault.Get carries
// no tenant predicate either, so the plaintext comes straight back.
//
// The doc comment on WorkflowIDBySlugInTenant already warned that its result
// "feeds HasGrant (the secret ACL) and the oauth tenant lookup" -- the codegen
// caller was fixed and these two were not.
//
// The run is the authoritative identity here: runs.workflow_id says which
// workflow is executing, and no slug collision can confuse it.
func TestSecretFetchDoesNotResolveWorkflowAcrossTenants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "xt.db")
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(ctx, silent, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)

	// ATTACKER's workflow is created FIRST so the victim's row is the most
	// recent one, which is the row the unscoped ORDER BY created_at DESC picks.
	if err := j.CreateWorkflowInTenant(ctx, "wf_attacker", "billing", "h", "0.1.0", json.RawMessage(`{}`), "tenant-attacker"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_victim", "billing", "h", "0.1.0", json.RawMessage(`{}`), "tenant-victim"); err != nil {
		t.Fatal(err)
	}
	// The victim's credential, and the victim's grant for it.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES (?,?,?,?,?)`,
		"cred_victim", "tenant-victim", "stripe", "svc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := j.GrantSecret(ctx, "wf_victim", "cred_victim", "victim-admin", ""); err != nil {
		t.Fatal(err)
	}
	// The attacker's run, executing the ATTACKER's workflow.
	if err := j.CreateRun(ctx, "run_attacker", "wf_attacker", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0xCD
	}
	v, err := vault.NewStore(vault.NewMemoryBackend(), masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, "cred_victim", []byte("sk_live_VICTIM_SECRET")); err != nil {
		t.Fatal(err)
	}

	// Sanity: the unscoped resolver really does cross the boundary, so the test
	// is exercising the path it claims to.
	if got, _ := j.WorkflowIDBySlug(ctx, "billing"); got != "wf_victim" {
		t.Fatalf("precondition: unscoped resolve returned %q, want wf_victim (the collision must land on the victim for this to be the disclosure path)", got)
	}

	// Strict mode, the default. The attacker's workflow has NO grants at all.
	sup := &Supervisor{
		WorkflowSlug:  "billing",
		RunID:         "run_attacker",
		Mode:          "live",
		Journal:       j,
		Vault:         v,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ACLPermissive: false,
	}
	var buf bytes.Buffer
	disp := &dispatcher{sup: sup, enc: wire.NewEncoder(&buf), writeMu: &sync.Mutex{}}
	req, err := wire.Wrap(1, 0, wire.KindSecretFetch, wire.SecretFetch{ID: "cred_victim"})
	if err != nil {
		t.Fatal(err)
	}
	if err := disp.handleSecretFetch(ctx, req); err != nil {
		t.Fatal(err)
	}
	frame, err := wire.NewDecoder(&buf).Decode()
	if err != nil {
		t.Fatal(err)
	}
	var sr wire.SecretReply
	if err := wire.Unwrap(frame, &sr); err != nil {
		t.Fatal(err)
	}

	if !sr.NotFound || len(sr.Value) > 0 {
		t.Fatalf("CROSS-TENANT SECRET DISCLOSURE: the attacker's run read the victim's credential (value=%q). The ACL gate resolved the workflow by slug across the tenant boundary and applied the victim's grant.", string(sr.Value))
	}
}

// TestStaleCrossTenantGrantStillDenied covers the defence-in-depth half. No slug
// collision here: the attacker's run resolves correctly to its own workflow. The
// grant row itself is cross-tenant, inserted directly the way one could have been
// before GrantSecret refused them. HasGrant only checks the (workflow,
// credential) pair and the grant table has no tenant column, so the grant alone
// would authorise; Vault.Get has no tenant predicate either. The explicit tenant
// equality check at the gate is what denies it.
func TestStaleCrossTenantGrantStillDenied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "stale.db")
	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(ctx, silent, "sqlite://"+dbPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := journal.New(db, journal.EngineSQLite)

	if err := j.CreateWorkflowInTenant(ctx, "wf_a", "attacker-flow", "h", "0.1.0", json.RawMessage(`{}`), "tenant-attacker"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES (?,?,?,?,?)`,
		"cred_victim", "tenant-victim", "stripe", "svc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_a", "wf_a", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	// GrantSecret would refuse this pair. Insert it raw, as a pre-guard row.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO workflow_secret_grants (workflow_id, credential_id, granted_by) VALUES (?,?,?)`,
		"wf_a", "cred_victim", "legacy"); err != nil {
		t.Fatal(err)
	}
	if err := j.GrantSecret(ctx, "wf_a", "cred_victim", "x", ""); err == nil {
		t.Fatal("precondition: GrantSecret should refuse this cross-tenant pair, so the raw row really is unreachable through the API")
	}

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0xCD
	}
	v, err := vault.NewStore(vault.NewMemoryBackend(), masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, "cred_victim", []byte("sk_live_STALE_GRANT")); err != nil {
		t.Fatal(err)
	}

	for _, permissive := range []bool{false, true} {
		sup := &Supervisor{
			WorkflowSlug: "attacker-flow", RunID: "run_a", Mode: "live",
			Journal: j, Vault: v,
			Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
			ACLPermissive: permissive,
		}
		var buf bytes.Buffer
		disp := &dispatcher{sup: sup, enc: wire.NewEncoder(&buf), writeMu: &sync.Mutex{}}
		req, _ := wire.Wrap(1, 0, wire.KindSecretFetch, wire.SecretFetch{ID: "cred_victim"})
		if err := disp.handleSecretFetch(ctx, req); err != nil {
			t.Fatal(err)
		}
		frame, err := wire.NewDecoder(&buf).Decode()
		if err != nil {
			t.Fatal(err)
		}
		var sr wire.SecretReply
		if err := wire.Unwrap(frame, &sr); err != nil {
			t.Fatal(err)
		}
		if !sr.NotFound || len(sr.Value) > 0 {
			t.Fatalf("permissive=%v: a stale cross-tenant grant row authorised the read (value=%q); the tenant equality check at the gate did not fire", permissive, string(sr.Value))
		}
	}
}
