// reactor is the Reactor CLI / daemon.
//
// Subcommands:
//
//	reactor migrate --db <url>                  run pending schema migrations
//	reactor replay  --db <url> --workflow-bin <p> <run-id>
//	                                              re-run a finalised run from cache
//	reactor dlq     list  --db <url> [--limit N] [--offset N] [--json]
//	reactor dlq     show  --db <url> <id>       show one dead-letter item
//	reactor lint    [--format text|json] [--rules em-dash,banned-call] <path>
//	reactor version                              print build version
//
// Future subcommands per the implementation plan:
//
//	init, serve, mcp install, vault rotate-master, vault export
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// Version is set via ldflags at release time:
//
//	go build -ldflags "-X main.Version=v0.1.0"
var Version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "reactor:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing subcommand")
	}
	cmd, rest := args[0], args[1:]
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	switch cmd {
	case "init":
		return cmdInit(rest)
	case "setup":
		return cmdSetup(ctx, log, rest)
	case "migrate":
		return cmdMigrate(ctx, log, rest)
	case "payload":
		return cmdPayload(ctx, rest)
	case "serve":
		return cmdServe(ctx, log, rest)
	case "worker":
		return cmdWorker(ctx, log, rest)
	case "artifact-publisher":
		return cmdArtifactPublisher(ctx, log, rest)
	case "workflow":
		return cmdWorkflow(ctx, log, rest)
	case "replay":
		return cmdReplay(ctx, log, rest)
	case "dlq":
		return cmdDLQ(ctx, log, rest)
	case "lint":
		return cmdLint(rest)
	case "vault":
		return cmdVault(ctx, log, rest)
	case "generate":
		return cmdGenerate(ctx, log, rest)
	case "ps":
		return cmdPS(ctx, log, rest)
	case "cancel":
		return cmdCancel(ctx, log, rest)
	case "mcp":
		return cmdMCP(ctx, log, rest)
	case "knowledge":
		return cmdKnowledge(ctx, log, rest)
	case "new":
		return cmdNew(ctx, log, rest)
	case "test":
		return cmdTest(ctx, log, rest)
	case "version":
		fmt.Println(Version)
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

func cmdMigrate(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL (sqlite://path or postgres://...)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbURL == "" {
		return errors.New("missing --db (or $REACTOR_DB_URL)")
	}
	log.Info("running migrations", "db", redactDB(*dbURL))
	if err := migrate.Up(ctx, log, *dbURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Info("migrations complete")
	return nil
}

// redactDB hides the password portion of a postgres URL for logs.
// The previous implementation indexed rawURL[:11] guarded only by
// len > 9, which panicked on URLs of length 10 ("postgres:/"). Use
// HasPrefix so partial matches and short strings don't blow up.
func redactDB(rawURL string) string {
	if strings.HasPrefix(rawURL, "postgres://") || strings.HasPrefix(rawURL, "postgresql://") {
		return "postgres://[redacted]"
	}
	return rawURL
}

func usage() {
	fmt.Fprintln(os.Stderr, `reactor: AI-built workflow automation

Usage:
  reactor init     [--root <dir>]                  bootstrap state dir + master key
  reactor migrate  --db <url>                      run pending schema migrations
  reactor payload  backfill-command-definitions    seal one bounded batch of historical command definitions
  reactor payload  backfill-run-logs               seal one bounded batch of historical run logs
  reactor serve    --db <url> [--addr 127.0.0.1:7777] run the daemon (HTTP + scheduler + rotation); --mode distributed enqueues
  reactor worker   --db <pg-url> [--concurrency N] distributed-mode worker: claim + run queued workflows (requires Postgres)
  reactor artifact-publisher --db <pg-url> --source-root <dir> --destination-root <dir>  publish reviewed artifacts to workers
  reactor workflow list/register/build             manage workflow registrations + binaries
  reactor replay   --db <url> <run-id>             show timeline for a finalised run
  reactor cancel   --db <url> <run-id>             stop a running or suspended run
  reactor dlq      list/show --db <url> [<id>]     dead-letter inspection
  reactor vault    list/audit/rotate               credential vault + rotation
  reactor lint     [--format text|json] <path>     lint workflow .go file or dir
  reactor knowledge add/list/search/show/...       grow + query the knowledge corpus
  reactor new      <template> <slug>               scaffold a workflow from a template
  reactor test     <slug> --against-run <id>|--latest  replay a journaled run; assert no divergence
  reactor mcp      install --client X --url URL   register the daemon's HTTP MCP endpoint (stdio is legacy)
  reactor version                                   print build version

Database URLs:
  sqlite://./reactor.db
  postgres://user:pass@host:5432/dbname

Environment:
  REACTOR_DB_URL                                      default --db value (legacy ARACHNE_DB_URL still read)
  REACTOR_MASTER_KEY                                  64-hex master key (overrides --master-key-file; legacy ARACHNE_MASTER_KEY still read)`)
}
