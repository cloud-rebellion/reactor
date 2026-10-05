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
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

// newACLEnv builds a journal + vault + a credential that the dispatcher
// can try to fetch. Workflow is created via the journal; whether the
// (workflow, credential) grant exists is the test's choice.
func newACLEnv(t *testing.T) (*journal.Journal, *vault.Store, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "acl.db")
	url := "sqlite://" + dbPath

	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	j := journal.New(db, journal.EngineSQLite)
	if err := j.CreateWorkflow(context.Background(), "wf_acl", "acl-test", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create wf: %v", err)
	}
	// The run row is load-bearing: the ACL gate resolves which workflow is
	// executing from runs.workflow_id, not from the supervisor's slug, because
	// slugs are unique only per tenant and the slug lookup crossed the boundary.
	// This harness previously set RunID to an id it never created, so the gate
	// was deciding against an unresolvable identity.
	if err := j.CreateRun(context.Background(), "run_acl", "wf_acl", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create run: %v", err)
	}
	// The vault here is in-memory, so nothing else creates the credentials
	// rows. GrantSecret/RevokeSecret now require both sides of a grant to
	// exist (a grant naming a resource that is not there was how phantom
	// grants got in via MCP and the CLI), so seed them explicitly.
	for _, id := range []string{"cred_secret", "cred_other"} {
		if _, err := db.ExecContext(context.Background(),
			`INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES (?,?,?,?,?)`,
			id, "default", "name-"+id, "svc", []byte("x")); err != nil {
			t.Fatalf("seed credential %s: %v", id, err)
		}
	}

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0xCD
	}
	v, err := vault.NewStore(vault.NewMemoryBackend(), masterKey)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if err := v.Put(context.Background(), "cred_secret", []byte("the-plaintext")); err != nil {
		t.Fatalf("vault put: %v", err)
	}
	return j, v, db
}

// runHandleSecretFetch constructs a dispatcher with the given ACL
// permissiveness, invokes handleSecretFetch with a SecretFetch frame
// for cred_secret against workflow slug acl-test, and returns the
// decoded SecretReply that came out of the dispatcher's writer.
func runHandleSecretFetch(t *testing.T, j *journal.Journal, v *vault.Store, permissive bool) wire.SecretReply {
	return runHandleSecretFetchOwned(t, j, v, permissive, "")
}

func runHandleSecretFetchOwned(t *testing.T, j *journal.Journal, v *vault.Store, permissive bool, leaseOwner string) wire.SecretReply {
	t.Helper()
	sup := &Supervisor{
		WorkflowSlug:  "acl-test",
		RunID:         "run_acl",
		Mode:          "live",
		Journal:       j,
		Vault:         v,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ACLPermissive: permissive,
		LeaseOwner:    leaseOwner,
	}
	var buf bytes.Buffer
	disp := &dispatcher{
		sup:     sup,
		enc:     wire.NewEncoder(&buf),
		writeMu: &sync.Mutex{},
	}

	req, err := wire.Wrap(1, 0, wire.KindSecretFetch, wire.SecretFetch{ID: "cred_secret"})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if err := disp.handleSecretFetch(context.Background(), req); err != nil {
		t.Fatalf("handleSecretFetch: %v", err)
	}

	dec := wire.NewDecoder(&buf)
	reply, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	var sr wire.SecretReply
	if err := wire.Unwrap(reply, &sr); err != nil {
		t.Fatalf("unwrap reply: %v", err)
	}
	return sr
}

func TestSecretFetchWireDeniesExpiredAndReplacedWorkerLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	j, v, db := newACLEnv(t)
	if err := j.GrantSecret(ctx, "wf_acl", "cred_secret", "test", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE runs SET status = 'queued' WHERE id = 'run_acl'`); err != nil {
		t.Fatal(err)
	}
	first, err := j.ClaimQueuedRuns(ctx, "worker-secret-a", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].RunID != "run_acl" {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	if reply := runHandleSecretFetchOwned(t, j, v, false, ""); !reply.NotFound || len(reply.Value) != 0 {
		t.Fatalf("lease-free local child received an owned secret: %+v", reply)
	}
	if reply := runHandleSecretFetchOwned(t, j, v, false, first[0].Owner); reply.NotFound || string(reply.Value) != "the-plaintext" {
		t.Fatalf("current worker secret reply: %+v", reply)
	}
	if err := j.ExtendLease(ctx, "run_acl", first[0].Owner, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if reply := runHandleSecretFetchOwned(t, j, v, false, first[0].Owner); !reply.NotFound || len(reply.Value) != 0 {
		t.Fatalf("expired worker received a secret before reap: %+v", reply)
	}
	if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap = %d, %v", n, err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-secret-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != "run_acl" {
		t.Fatalf("replacement claim = %+v, %v", second, err)
	}
	if reply := runHandleSecretFetchOwned(t, j, v, false, first[0].Owner); !reply.NotFound || len(reply.Value) != 0 {
		t.Fatalf("replaced worker received a secret: %+v", reply)
	}
	if reply := runHandleSecretFetchOwned(t, j, v, false, second[0].Owner); reply.NotFound || string(reply.Value) != "the-plaintext" {
		t.Fatalf("replacement worker secret reply: %+v", reply)
	}
}

func TestSecretFetchEmptyACLStrictDeniesByDefault(t *testing.T) {
	t.Parallel()
	j, v, _ := newACLEnv(t)

	reply := runHandleSecretFetch(t, j, v, false)
	if !reply.NotFound {
		t.Fatalf("strict mode + empty grants table should deny; got reply=%+v", reply)
	}
	if len(reply.Value) != 0 {
		t.Fatalf("strict mode leaked plaintext: %q", reply.Value)
	}
}

func TestSecretFetchEmptyACLPermissiveAllows(t *testing.T) {
	t.Parallel()
	j, v, _ := newACLEnv(t)

	reply := runHandleSecretFetch(t, j, v, true)
	if reply.NotFound {
		t.Fatalf("permissive mode should allow on empty table; got NotFound")
	}
	if string(reply.Value) != "the-plaintext" {
		t.Fatalf("plaintext mismatch: got %q want %q", reply.Value, "the-plaintext")
	}
}

func TestSecretFetchPermissiveDeniesGrantProbeError(t *testing.T) {
	t.Parallel()
	j, v, db := newACLEnv(t)

	// A permissive install may allow the explicit empty-table migration fallback,
	// but it must not treat an actual grant-probe failure as an empty table. Drop
	// the grants table to reproduce a database/schema error after the workflow
	// and credential tenant checks have already succeeded.
	if _, err := db.ExecContext(context.Background(), `DROP TABLE workflow_secret_grants`); err != nil {
		t.Fatalf("drop grants table: %v", err)
	}

	reply := runHandleSecretFetch(t, j, v, true)
	if !reply.NotFound {
		t.Fatalf("permissive mode allowed a secret when the grant probe failed: reply=%+v", reply)
	}
	if len(reply.Value) != 0 {
		t.Fatalf("grant probe failure leaked plaintext: %q", reply.Value)
	}
}

func TestSecretFetchExplicitGrantAllowsRegardlessOfPermissive(t *testing.T) {
	t.Parallel()
	j, v, _ := newACLEnv(t)
	if err := j.GrantSecret(context.Background(), "wf_acl", "cred_secret", "test", ""); err != nil {
		t.Fatalf("grant: %v", err)
	}

	reply := runHandleSecretFetch(t, j, v, false)
	if reply.NotFound {
		t.Fatalf("explicit grant should allow under strict mode; got NotFound")
	}
	if string(reply.Value) != "the-plaintext" {
		t.Fatalf("plaintext mismatch: got %q want %q", reply.Value, "the-plaintext")
	}
}

func TestSecretFetchNonEmptyACLWithoutGrantDenies(t *testing.T) {
	t.Parallel()
	j, v, _ := newACLEnv(t)
	// Seed an unrelated grant so the table is non-empty; this
	// disables the empty-table fallback for both modes.
	if err := j.GrantSecret(context.Background(), "wf_acl", "cred_other", "test", ""); err != nil {
		t.Fatalf("grant: %v", err)
	}

	for _, permissive := range []bool{false, true} {
		reply := runHandleSecretFetch(t, j, v, permissive)
		if !reply.NotFound {
			t.Fatalf("permissive=%v: missing grant should deny even on non-empty table; got %+v", permissive, reply)
		}
	}
}
