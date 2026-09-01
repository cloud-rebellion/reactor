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

	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

// cmdDLQ dispatches the dlq subcommand group: list / show / retry.
//
// retry re-runs the workflow with the same RunID. The supervisor's
// journal cache short-circuits previously-succeeded steps; the failed
// step has no succeeded output_jsonb row so it re-executes. On run
// success, the dead_letter row is deleted; on failure, last_rotation_
// error semantics apply (run terminal flips to failed_dlq again).
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

// cmdDLQRetry re-runs the workflow that owns the dead-letter row by
// spawning a fresh supervisor with the original RunID. The supervisor's
// journal cache short-circuits every previously-succeeded step; the
// failed step has no succeeded output_jsonb row so the closure runs
// again. On success, the dead_letter row is removed.
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

	item, err := j.GetDeadLetterItem(ctx, dlqID)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("dlq retry: %s not found", dlqID)
		}
		return err
	}

	run, err := j.GetRun(ctx, item.RunID)
	if err != nil {
		return fmt.Errorf("dlq retry: get run: %w", err)
	}
	slug, err := j.WorkflowSlugByID(ctx, run.WorkflowID)
	if err != nil {
		return fmt.Errorf("dlq retry: workflow lookup: %w", err)
	}
	if _, err := j.ValidateRunWorkflowArtifact(ctx, run); err != nil {
		_ = j.LogRunArtifactFence(context.WithoutCancel(ctx), run.ID)
		return fmt.Errorf("dlq retry: refused by workflow artifact fence: %w", err)
	}
	if enabled, err := j.IsWorkflowEnabled(ctx, run.WorkflowID); err != nil {
		return fmt.Errorf("dlq retry: workflow enabled gate: %w", err)
	} else if !enabled {
		return errors.New("dlq retry: workflow is disabled")
	}
	if err := j.CheckWorkflowEnqueueAllowed(ctx, run.WorkflowID); err != nil {
		return fmt.Errorf("dlq retry: workflow quota gate: %w", err)
	}
	if allowed, limit, err := j.CheckWorkflowRateLimit(ctx, run.WorkflowID); err != nil {
		return fmt.Errorf("dlq retry: workflow rate-limit gate: %w", err)
	} else if !allowed {
		return fmt.Errorf("dlq retry: workflow rate limit reached (%d/minute)", limit)
	}

	if engine == migrate.EnginePostgres {
		// PostgreSQL is the serve/worker split. Never execute synchronously in
		// this CLI process without a lease: a terminal disconnect would leave a
		// running row no worker can reclaim. The worker resolves and verifies the
		// immutable artifact again immediately before execution.
		claimed, err := j.StartDeadLetterRetryQueuedItem(ctx, item.RunID, item.ID)
		if err != nil {
			return fmt.Errorf("dlq retry: enqueue run: %w", err)
		}
		if !claimed {
			return errors.New("dlq retry: run is not in the current failed_dlq state")
		}
		fmt.Printf("retry %s -> run %s status=queued\n", dlqID, item.RunID)
		return nil
	}

	if *root == "" {
		return errors.New("dlq retry: missing --root (and HOME unset)")
	}
	masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
	if err != nil {
		return err
	}
	// Local mode opens the same vault + immutable binary registry as serve.
	store, vaultCloser, err := openVaultStore(*dbURL, masterHex)
	if err != nil {
		return err
	}
	defer vaultCloser()
	reg := registry.New(filepath.Join(*root, "workflows"))
	binaryPath, err := reg.ArtifactPath(slug, run.WorkflowArtifactSHA256)
	if err != nil {
		_ = j.LogRunArtifactFence(context.WithoutCancel(ctx), run.ID)
		return fmt.Errorf("dlq retry: refused by workflow artifact fence: immutable artifact failed verification")
	}

	// Atomically claim the redrive and open a fresh bounded retry generation.
	// Artifact validation above must happen first: an untrusted executable must
	// not consume the operator's redrive claim/budget.
	claimed, err := j.StartDeadLetterRetryItem(ctx, item.RunID, item.ID)
	if err != nil {
		return fmt.Errorf("dlq retry: claim run: %w", err)
	}
	if !claimed {
		return errors.New("dlq retry: run is already executing or was cancelled")
	}

	signKey, _ := decodeMasterKey(masterHex)
	sup := supervisor.Supervisor{
		BinaryPath:       binaryPath,
		WorkflowSlug:     slug,
		RunID:            item.RunID,
		Mode:             "live",
		Journal:          j,
		Vault:            store,
		Log:              log,
		Input:            run.TriggerMeta,
		SignalSigningKey: signKey,
	}
	status, err := sup.Run(ctx)
	if err != nil {
		return fmt.Errorf("dlq retry: %w", err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("dlq retry: %w", ctx.Err())
	}
	fmt.Printf("retry %s -> run %s status=%s\n", dlqID, item.RunID, status)
	if status == "succeeded" {
		cleared, err := j.DeleteDeadLettersByRun(context.WithoutCancel(ctx), item.RunID)
		if err != nil {
			log.Warn("dlq retry: cleanup failed", "err", err)
		} else {
			fmt.Printf("cleared %d dead-letter item(s) for run %s\n", cleared, item.RunID)
		}
	}
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
	return journal.New(db, jEngine), closer, nil
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
