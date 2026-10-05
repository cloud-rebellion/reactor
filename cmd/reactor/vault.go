package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/rotators"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/vault"
)

// cmdVault dispatches the vault subcommand group: list / rotate / audit.
//
// Manual rotation runs through rotators.Runner.RotateOne so the CLI
// path mirrors the scheduler path exactly: same provider lookup, same
// delivery, same audit rows.
func cmdVault(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("vault: missing subcommand (list|rotate|audit)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdVaultList(ctx, log, rest)
	case "add":
		return cmdVaultAdd(ctx, log, rest)
	case "rotate":
		return cmdVaultRotate(ctx, log, rest)
	case "audit":
		return cmdVaultAudit(ctx, log, rest)
	case "grant":
		return cmdVaultGrant(ctx, log, rest)
	case "revoke":
		return cmdVaultRevoke(ctx, log, rest)
	case "grants":
		return cmdVaultGrants(ctx, log, rest)
	default:
		return fmt.Errorf("vault: unknown subcommand %q (want list|add|rotate|audit|grant|revoke|grants)", sub)
	}
}

func cmdVaultList(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("vault list", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}

	repo, closer, err := openCredentials(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	creds, err := repo.List(ctx)
	if err != nil {
		return err
	}

	if *asJSON {
		if creds == nil {
			creds = []credentials.Credential{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(creds)
	}
	if len(creds) == 0 {
		fmt.Println("(no credentials)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "ID\tNAME\tPROVIDER\tAUTO\tINTERVAL\tLAST_ROTATED\tERROR")
	for _, c := range creds {
		auto := "off"
		if c.AutoRotate {
			auto = "on"
		}
		last := "-"
		if !c.LastRotatedAt.IsZero() {
			last = c.LastRotatedAt.UTC().Format("2006-01-02T15:04Z")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%dd\t%s\t%s\n",
			c.ID, c.Name, c.Provider, auto, c.RotationIntervalDays, last,
			truncate(c.LastRotationError, 80),
		)
	}
	return nil
}

// cmdVaultAdd registers a credential row + stores its plaintext in the
// vault. Used by `make demo` to seed the welcome-customer demo's
// expected secrets so the workflow doesn't crash on vault.MustGet.
//
// Flags:
//
//	--db        database URL
//	--root      state dir (master.key location; defaults to $HOME/.reactor)
//	--master-key  hex-encoded master key (overrides root/master.key)
//	--tenant    owning tenant (default "default")
//	--name      credential display name (required; also the default id)
//	--service   logical service tag (e.g. "stripe", "resend")
//	--provider  rotator provider (default "manual")
//	--auto-rotate  enable scheduler-driven rotation
//	--interval-days  rotation interval when auto-rotate is on
//	--value     literal secret value (or read from --value-file / stdin)
//	--value-file  path to a file with the secret bytes
//	--id        id passed to vault.MustGet (defaults to --name)
func cmdVaultAdd(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("vault add", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state directory (for master.key lookup)")
	masterKeyFile := fs.String("master-key-file", "", "path to master key file")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "hex-encoded master key (overrides --master-key-file)")
	tenantID := fs.String("tenant", journal.DefaultTenant, "owning tenant id")
	id := fs.String("id", "", "credential id used by vault.MustGet (defaults to --name)")
	name := fs.String("name", "", "credential display name (required)")
	service := fs.String("service", "", "logical service tag (e.g. stripe, resend)")
	provider := fs.String("provider", "manual", "rotator provider (manual, shared-secret, ...)")
	autoRotate := fs.Bool("auto-rotate", false, "enable scheduled rotation")
	allowLocalMint := fs.Bool("allow-local-mint", false, "acknowledge that a local-mint provider may replace the stored value")
	intervalDays := fs.Int("interval-days", 0, "rotation interval in days (auto-rotate must be set)")
	value := fs.String("value", "", "literal secret value (or use --value-file)")
	valueFile := fs.String("value-file", "", "path to file containing the secret value")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}
	if *name == "" {
		return errors.New("missing --name")
	}
	*tenantID = strings.TrimSpace(*tenantID)
	if *tenantID == "" {
		return errors.New("missing --tenant")
	}
	if *autoRotate && *intervalDays <= 0 {
		return errors.New("--auto-rotate requires --interval-days > 0")
	}
	if p, perr := rotators.Get(*provider); perr == nil && rotators.MintsValueLocally(p) && *autoRotate && !*allowLocalMint {
		return fmt.Errorf("provider %q mints replacement values locally; --auto-rotate requires --allow-local-mint acknowledgement", *provider)
	}
	if *value == "" && *valueFile == "" {
		return errors.New("missing --value or --value-file")
	}

	plaintext := []byte(*value)
	if *valueFile != "" {
		raw, err := os.ReadFile(*valueFile)
		if err != nil {
			return fmt.Errorf("read --value-file: %w", err)
		}
		plaintext = raw
	}

	// Default id == name so workflows can call vault.MustGet("crm-api-key")
	// without first looking up the random cred_<hex> row id. Operators
	// who want decoupled ids can pass --id explicitly.
	if *id == "" {
		*id = *name
	}

	masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
	if err != nil {
		return err
	}

	repo, repoCloser, err := openCredentials(*dbURL)
	if err != nil {
		return err
	}
	defer repoCloser()

	if err := repo.Create(ctx, credentials.CreateParams{
		ID:                   *id,
		Name:                 *name,
		TenantID:             *tenantID,
		Service:              *service,
		Provider:             *provider,
		AllowLocalMint:       *allowLocalMint,
		AutoRotate:           *autoRotate,
		RotationIntervalDays: *intervalDays,
	}); err != nil {
		return err
	}

	// Everything from here can fail AFTER the credentials row exists, so each
	// exit rolls it back. Without that the operator is left with a credential
	// that has no secret, cannot be deleted once it has audit history, and whose
	// identifier cannot be reused (the id defaults to the name), which is a
	// state only hand-written SQL could clear. The dashboard path got this
	// rollback first; the CLI has the same create-then-put ordering and needs it
	// just as much.
	rollback := func(cause error) error {
		if derr := repo.Delete(ctx, *id); derr != nil {
			return fmt.Errorf("%w (rollback also failed, orphan row %q remains: %v)", cause, *id, derr)
		}
		return cause
	}

	store, vaultCloser, err := openVaultStore(*dbURL, masterHex)
	if err != nil {
		return rollback(err)
	}
	defer vaultCloser()
	if err := store.Put(ctx, *id, plaintext); err != nil {
		return rollback(fmt.Errorf("vault: put %s: %w", *id, err))
	}
	// docs/security.md lists `operator` / `reactor vault add` as an audited
	// actor, and the CLI wrote no audit row at all: the "who touched which
	// secret, when" trail had holes exactly where a human touched secrets by
	// hand, while the dashboard path audited correctly.
	auditCLI(ctx, repo, *id, "create.cli")

	fmt.Printf("added %s (id=%s, tenant=%s, auto_rotate=%t)\n", *name, *id, *tenantID, *autoRotate)
	return nil
}

// auditCLI records an operator action from the CLI. Best-effort: a failed audit
// write must not fail the command the operator already completed, but it is
// logged rather than swallowed so a broken trail is discoverable.
func auditCLI(ctx context.Context, repo *credentials.Repo, credentialID, action string) {
	if repo == nil || credentialID == "" {
		return
	}
	actor := os.Getenv("USER")
	if actor == "" {
		actor = os.Getenv("LOGNAME")
	}
	if err := repo.AppendAudit(ctx, credentials.AuditEntry{
		CredentialID: credentialID,
		Action:       action,
		ActorKind:    "operator",
		ActorID:      actor,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit row for %s not written: %v\n", action, err)
	}
}

func cmdVaultRotate(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("vault rotate", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	masterHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex-encoded master key")
	allowLocalMint := fs.Bool("allow-local-mint", false, "acknowledge that a local-mint provider will replace the stored value")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}
	if fs.NArg() == 0 {
		return errors.New("missing <credential-id>")
	}
	id := fs.Arg(0)

	store, closer, err := openVaultStore(*dbURL, *masterHex)
	if err != nil {
		return err
	}
	defer closer()
	repo, _, err := openCredentialsFromDBURL(*dbURL)
	if err != nil {
		return err
	}

	runner := &rotators.Runner{
		Repo:  repo,
		Vault: store,
		Log:   log,
	}
	if err := runner.RotateOneWithLocalMintAck(ctx, id, *allowLocalMint); err != nil {
		return err
	}
	fmt.Printf("rotated %s\n", id)
	return nil
}

func cmdVaultAudit(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("vault audit", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	limit := fs.Int("limit", 50, "max audit rows to return")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}
	if fs.NArg() == 0 {
		return errors.New("missing <credential-id>")
	}
	id := fs.Arg(0)

	repo, closer, err := openCredentials(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	// Confirm the credential exists before listing audit. Otherwise
	// `vault audit <typo>` returns "(no audit rows)" / `[]` with exit
	// 0 and the operator never learns the id was wrong.
	if _, err := repo.Get(ctx, id); err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return fmt.Errorf("vault audit: credential %q not found", id)
		}
		return err
	}

	rows, err := repo.ListAudit(ctx, id, *limit)
	if err != nil {
		return err
	}

	if *asJSON {
		if rows == nil {
			rows = []credentials.AuditEntry{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Println("(no audit rows)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "AT\tACTION\tACTOR\tDETAIL")
	for _, r := range rows {
		actor := r.ActorKind
		if r.ActorID != "" {
			actor = r.ActorKind + ":" + r.ActorID
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			r.At.UTC().Format("2006-01-02T15:04:05Z"), r.Action, actor, truncate(string(r.Detail), 120),
		)
	}
	return nil
}

// cmdVaultGrant records that a workflow may read a credential. The
// supervisor's handleSecretFetch checks this table at every Vault.Get
// boundary; without a matching grant the workflow gets NotFound.
//
//	reactor vault grant --db <url> --tenant <tenant> <workflow-slug> <credential-id> [--note <note>]
func cmdVaultGrant(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("vault grant", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	tenantID := fs.String("tenant", journal.DefaultTenant, "tenant that owns the workflow and credential")
	by := fs.String("by", os.Getenv("USER"), "actor identifier (defaults to $USER)")
	note := fs.String("note", "", "free-form note attached to the grant")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("vault grant: missing --db (or $REACTOR_DB_URL)")
	}
	*tenantID = strings.TrimSpace(*tenantID)
	if *tenantID == "" {
		return errors.New("vault grant: missing --tenant")
	}
	if fs.NArg() != 2 {
		return errors.New("vault grant: usage: <workflow-slug> <credential-id>")
	}
	slug, credID := fs.Arg(0), fs.Arg(1)

	j, closer, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	wfID, err := j.WorkflowIDBySlugInTenant(ctx, slug, *tenantID)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("vault grant: workflow %q not registered in tenant %q", slug, *tenantID)
		}
		return fmt.Errorf("vault grant: resolve workflow %q in tenant %q: %w", slug, *tenantID, err)
	}
	if err := j.GrantSecret(ctx, wfID, credID, *by, *note); err != nil {
		return err
	}
	if repo, repoCloser, rerr := openCredentials(*dbURL); rerr == nil {
		defer repoCloser()
		auditCLI(ctx, repo, credID, "grant.cli")
	}
	fmt.Printf("granted %s -> %s (workflow_id=%s, tenant=%s)\n", slug, credID, wfID, *tenantID)
	return nil
}

// cmdVaultRevoke removes a grant. The tenant is explicit so duplicate slugs
// cannot resolve to another tenant's workflow.
func cmdVaultRevoke(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("vault revoke", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	tenantID := fs.String("tenant", journal.DefaultTenant, "tenant that owns the workflow and credential")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("vault revoke: missing --db (or $REACTOR_DB_URL)")
	}
	*tenantID = strings.TrimSpace(*tenantID)
	if *tenantID == "" {
		return errors.New("vault revoke: missing --tenant")
	}
	if fs.NArg() != 2 {
		return errors.New("vault revoke: usage: <workflow-slug> <credential-id>")
	}
	slug, credID := fs.Arg(0), fs.Arg(1)

	j, closer, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	wfID, err := j.WorkflowIDBySlugInTenant(ctx, slug, *tenantID)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("vault revoke: workflow %q not registered in tenant %q", slug, *tenantID)
		}
		return fmt.Errorf("vault revoke: resolve workflow %q in tenant %q: %w", slug, *tenantID, err)
	}
	if err := j.RevokeSecret(ctx, wfID, credID); err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("vault revoke: no grant for %s -> %s", slug, credID)
		}
		return err
	}
	if repo, repoCloser, rerr := openCredentials(*dbURL); rerr == nil {
		defer repoCloser()
		auditCLI(ctx, repo, credID, "revoke.cli")
	}
	fmt.Printf("revoked %s -> %s\n", slug, credID)
	return nil
}

// cmdVaultGrants lists every grant or filters to one workflow. The optional
// tenant makes a filtered lookup deterministic when two tenants reuse a slug.
func cmdVaultGrants(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("vault grants", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	tenantID := fs.String("tenant", journal.DefaultTenant, "tenant that owns the filtered workflow")
	asJSON := fs.Bool("json", false, "emit JSON")
	workflow := fs.String("workflow", "", "filter to one workflow slug")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("vault grants: missing --db (or $REACTOR_DB_URL)")
	}
	*tenantID = strings.TrimSpace(*tenantID)
	if *tenantID == "" {
		return errors.New("vault grants: missing --tenant")
	}

	j, closer, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	var grants []journal.Grant
	if *workflow != "" {
		wfID, err := j.WorkflowIDBySlugInTenant(ctx, *workflow, *tenantID)
		if err != nil {
			return fmt.Errorf("vault grants: resolve workflow %q in tenant %q: %w", *workflow, *tenantID, err)
		}
		grants, err = j.ListGrantsForWorkflow(ctx, wfID)
		if err != nil {
			return err
		}
	} else {
		grants, err = j.ListGrants(ctx)
		if err != nil {
			return err
		}
	}

	if *asJSON {
		if grants == nil {
			grants = []journal.Grant{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(grants)
	}
	if len(grants) == 0 {
		fmt.Println("(no grants; strict mode denies secret fetches; legacy permissive mode allows same-tenant fetches)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "WORKFLOW_ID\tCREDENTIAL_ID\tGRANTED_AT\tBY\tNOTE")
	for _, g := range grants {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			g.WorkflowID, g.CredentialID,
			g.GrantedAt.UTC().Format("2006-01-02T15:04Z"),
			g.GrantedBy, truncate(g.Note, 80))
	}
	return nil
}

// openCredentials wires migrate.Open + credentials.New for read-only
// commands. Returns a closer that callers must defer.
func openCredentials(dbURL string) (*credentials.Repo, func(), error) {
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		return nil, nil, err
	}
	closer := func() { _ = db.Close() }
	credEngine := credentials.EngineSQLite
	if engine == migrate.EnginePostgres {
		credEngine = credentials.EnginePostgres
	}
	return credentials.New(db, credEngine), closer, nil
}

// openCredentialsFromDBURL reuses an already-open DB if possible by
// opening a new connection (sql.DB pools internally so this is fine).
// Used by `vault rotate` which also opens a vault.Store.
func openCredentialsFromDBURL(dbURL string) (*credentials.Repo, func(), error) {
	return openCredentials(dbURL)
}

// openVaultStore wires the vault.Store on top of a SQL-backed Backend
// so the rotation CLI's Vault.Rotate writes the new encrypted blob
// straight into credentials.blob (durable across runs).
//
// Master key comes from --master-key or ARACHNE_MASTER_KEY (32 hex bytes =
// 64 hex chars).
func openVaultStore(dbURL, masterHex string) (*vault.Store, func(), error) {
	if masterHex == "" {
		return nil, nil, errors.New("missing --master-key (or ARACHNE_MASTER_KEY env var)")
	}
	masterKey, err := decodeMasterKey(masterHex)
	if err != nil {
		return nil, nil, err
	}
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		return nil, nil, err
	}
	vaultEngine := vault.SQLEngineSQLite
	if engine == migrate.EnginePostgres {
		vaultEngine = vault.SQLEnginePostgres
	}
	backend := vault.NewSQLBackend(db, vaultEngine)
	store, err := vault.NewStore(backend, masterKey)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return store, func() { _ = db.Close() }, nil
}

func decodeMasterKey(hexed string) ([]byte, error) {
	const want = 32
	if len(hexed) != want*2 {
		return nil, fmt.Errorf("master key must be %d hex chars (got %d)", want*2, len(hexed))
	}
	out := make([]byte, want)
	for i := 0; i < want; i++ {
		var b byte
		_, err := fmt.Sscanf(hexed[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return nil, fmt.Errorf("bad hex at byte %d: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}
