package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

// cmdDLQ dispatches the dlq subcommand group: list / show / retry.
//
// retry re-runs the workflow with the same RunID through the canonical
// dispatcher. The supervisor's journal cache short-circuits previously-
// succeeded steps; the failed step has no succeeded output_jsonb row so it
// re-executes. On run success, the dead_letter row is deleted; on failure,
// the run terminal flips back to failed_dlq through the normal repair path.
func cmdDLQ(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("dlq: missing subcommand (list|show|retry)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdDLQList(ctx, log, rest)
	case "show":
		return cmdDLQShow(ctx, log, rest)
	case "retry":
		return cmdDLQRetry(ctx, log, rest)
	default:
		return fmt.Errorf("dlq: unknown subcommand %q (want list|show|retry)", sub)
	}
}

func cmdDLQList(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("dlq list", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state root containing master.key")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	limit := fs.Int("limit", 50, "max items to return")
	offset := fs.Int("offset", 0, "rows to skip")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}

	j, closer, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer closer()
	if err := loadDLQReadPayloadKey(ctx, j, *root, *masterKeyFile); err != nil {
		return err
	}

	items, err := j.ListDeadLetterItems(ctx, *limit, *offset)
	if err != nil {
		return err
	}
	log.Debug("dlq list", "count", len(items), "db", redactDB(*dbURL))

	if *asJSON {
		// JSON consumers expect an array; a nil slice would marshal to
		// `null` and break `.length` / `.forEach` callers. Initialise
		// to an empty slice so the on-wire shape is always `[]` or `[ ... ]`.
		if items == nil {
			items = []journal.DeadLetterItem{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(items)
	}
	if len(items) == 0 {
		fmt.Println("(no dead-letter items)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "ID\tRUN_ID\tSTEP\tMOVED_AT\tERROR")
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			it.ID, it.RunID, it.StepName,
			it.MovedAt.UTC().Format("2006-01-02T15:04:05Z"),
			truncate(it.ErrorText, 80),
		)
	}
	return nil
}

func cmdDLQShow(ctx context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("dlq show", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state root containing master.key")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	asJSON := fs.Bool("json", false, "emit JSON")
	// stdlib flag.Parse stops at the first non-flag arg. Users naturally
	// type `reactor dlq show --db ... <id> --json` (positional in the
	// middle), so reorder args so flags lead and positionals trail.
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}
	if fs.NArg() == 0 {
		return errors.New("missing <id>")
	}
	id := fs.Arg(0)

	j, closer, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer closer()
	if err := loadDLQReadPayloadKey(ctx, j, *root, *masterKeyFile); err != nil {
		return err
	}

	item, err := j.GetDeadLetterItem(ctx, id)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("dlq: %s not found", id)
		}
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(item)
	}
	fmt.Printf("ID:        %s\n", item.ID)
	fmt.Printf("Run:       %s\n", item.RunID)
	fmt.Printf("Step:      %s\n", item.StepName)
	fmt.Printf("Moved at:  %s\n", item.MovedAt.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Printf("Error:     %s\n", item.ErrorText)
	fmt.Printf("Payload:   %s\n", string(item.Payload))
	return nil
}

func loadDLQReadPayloadKey(ctx context.Context, j *journal.Journal, root, masterKeyFile string) error {
	hasKey, err := j.HasPayloadKey(ctx)
	if err != nil || !hasKey {
		return err
	}
	masterHex, err := loadMasterKey(envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), masterKeyFile, root)
	if err != nil {
		return fmt.Errorf("dlq: journal payload key: %w", err)
	}
	master, err := decodeMasterKey(masterHex)
	if err != nil {
		return fmt.Errorf("dlq: journal payload key: %w", err)
	}
	var previous []byte
	if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
		previous, err = decodeMasterKey(prevHex)
		if err != nil {
			return fmt.Errorf("dlq: previous journal payload key: %w", err)
		}
	}
	if err := j.LoadPayloadEncryption(ctx, master, previous); err != nil {
		return fmt.Errorf("dlq: journal payload key: %w", err)
	}
	return nil
}

// cmdDLQRetry re-runs the workflow that owns the dead-letter row through the
// same Dispatcher path used by HTTP MCP, dashboard, webhook and cron. The
// dispatcher resolves and verifies the pinned artifact immediately before the
// retry, applies the normal admission gates, and owns the terminal/DLQ repair
// lifecycle. This command is only an adapter for flags and output.
//
//	reactor dlq retry --db <url> --master-key-file <path> <dlq-id>
//
// SQLite/local mode resolves and executes the pinned binary synchronously.
// PostgreSQL is distributed mode: the CLI only authorizes + queues the exact
// redrive item so a leased worker performs execution.
func cmdDLQRetry(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("dlq retry", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state root (workflows/ + master.key live here)")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file)")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("dlq retry: missing --db (or $REACTOR_DB_URL)")
	}
	if fs.NArg() == 0 {
		return errors.New("dlq retry: missing <dlq-id>")
	}
	dlqID := fs.Arg(0)
	engine, err := migrate.EngineFromURL(*dbURL)
	if err != nil {
		return fmt.Errorf("dlq retry: database URL: %w", err)
	}

	j, closer, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer closer()

	if *root == "" {
		return errors.New("dlq retry: missing --root (and HOME unset)")
	}
	hasPayloadKey, err := j.HasPayloadKey(ctx)
	if err != nil {
		return err
	}
	var masterHex string
	if hasPayloadKey || engine != migrate.EnginePostgres {
		masterHex, err = loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
		if err != nil {
			return err
		}
		masterKey, decodeErr := decodeMasterKey(masterHex)
		if decodeErr != nil {
			return decodeErr
		}
		var previous []byte
		if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
			previous, err = decodeMasterKey(prevHex)
			if err != nil {
				return fmt.Errorf("REACTOR_MASTER_KEY_PREVIOUS: %w", err)
			}
		}
		if err := j.LoadPayloadEncryption(ctx, masterKey, previous); err != nil {
			return fmt.Errorf("dlq retry: journal payload key: %w", err)
		}
	}
	item, err := j.GetDeadLetterItem(ctx, dlqID)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("dlq retry: %s not found", dlqID)
		}
		return err
	}
	reg := registry.New(filepath.Join(*root, "workflows"))
	var vaultReader supervisor.VaultReader
	var signalSigningKey []byte
	var vaultCloser func()
	if engine != migrate.EnginePostgres {
		store, closeVault, openErr := openVaultStore(*dbURL, masterHex)
		if openErr != nil {
			return openErr
		}
		vaultReader = store
		vaultCloser = closeVault
		signalSigningKey, _ = decodeMasterKey(masterHex)
		defer vaultCloser()
	}

	d := &dispatcher.Dispatcher{
		Journal:               j,
		Resolver:              &dispatcher.SQLResolver{Journal: j},
		ArtifactPath:          reg.ArtifactPath,
		ArtifactPathForTenant: reg.TenantArtifactPath,
		IntegrityCheck: func(ctx context.Context, slug string, version journal.WorkflowVersion) error {
			tenant, err := j.WorkflowTenant(ctx, version.WorkflowID)
			if err != nil {
				return fmt.Errorf("resolve workflow tenant for source proof: %w", err)
			}
			return workflowproof.ValidateVersionForTenant(*root, slug, tenant, version)
		},
		Log:     log,
		Enqueue: engine == migrate.EnginePostgres,
		Sup: supervisor.Supervisor{
			Vault:            vaultReader,
			SignalSigningKey: signalSigningKey,
			Limits: supervisor.ResourceLimits{
				CgroupRoot:    os.Getenv("REACTOR_CGROUP_ROOT"),
				RequireCgroup: os.Getenv("REACTOR_REQUIRE_WORKFLOW_CGROUP") == "1",
			},
		},
	}
	status, err := d.RetryDeadLetter(ctx, dlqID)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("dlq retry: %s not found", dlqID)
		}
		return fmt.Errorf("dlq retry: %w", err)
	}
	fmt.Printf("retry %s -> run %s status=%s\n", dlqID, item.RunID, status)
	return nil
}

// openJournal centralises the migrate.Open + journal.New wiring used by
// every subcommand that needs to read the schedules / runs / dead_letter
// tables. Returns a closer that callers must defer.
func openJournal(dbURL string) (*journal.Journal, func(), error) {
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		return nil, nil, err
	}
	closer := func() { _ = db.Close() }
	jEngine := journal.EngineSQLite
	if engine == migrate.EnginePostgres {
		jEngine = journal.EnginePostgres
	}
	j := journal.New(db, jEngine)
	if masterHex := envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"); masterHex != "" {
		master, err := decodeMasterKey(masterHex)
		if err != nil {
			closer()
			return nil, nil, err
		}
		var previous []byte
		if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
			previous, err = decodeMasterKey(prevHex)
			if err != nil {
				closer()
				return nil, nil, fmt.Errorf("REACTOR_MASTER_KEY_PREVIOUS: %w", err)
			}
		}
		if err := j.LoadPayloadEncryption(context.Background(), master, previous); err != nil {
			closer()
			return nil, nil, err
		}
	}
	return j, closer, nil
}

// truncate trims s to n runes plus an ellipsis when it overflows. Used
// for the list command's error column so a multi-line stack trace doesn't
// blow out the table.
func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// boolFlags are the bool-shaped flags every CLI subcommand recognises.
// reorderArgs hoists these from anywhere in the argv to the front so a
// user can write the natural `dlq show --db <url> <id> --json` instead
// of being forced to put the bool flag before the positional.
var boolFlags = map[string]bool{
	"--json":        true,
	"-json":         true,
	"--latest":      true,
	"-latest":       true,
	"--echo-prompt": true,
	"-echo-prompt":  true,
	"--allow-write": true,
	"-allow-write":  true,
	"--apply":       true,
	"-apply":        true,
	"--gold":        true,
	"-gold":         true,
	"--off":         true,
	"-off":          true,
	"--no-commit":   true,
	"-no-commit":    true,
	"--auto-rotate": true,
	"-auto-rotate":  true,
	"-h":            true,
	"--help":        true,
}

// reorderArgs hoists `--name=value` tokens and known bool flags ahead
// of positional tokens. `--name value` (string flag with following
// value) is left in place; users still need to put those before the
// first positional, which matches the stdlib `flag` package's contract.
//
// Anything past `--` is treated as positional verbatim.
func reorderArgs(args []string) []string {
	flags := []string{}
	pos := []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			pos = append(pos, args[i+1:]...)
			return append(flags, pos...)
		case strings.Contains(a, "=") && strings.HasPrefix(a, "-"):
			flags = append(flags, a)
		case boolFlags[a]:
			flags = append(flags, a)
		default:
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}
