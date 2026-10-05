package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
)

// cmdPayload owns explicit, bounded storage-only encryption backfills. It
// never initializes a new journal key or starts a workflow/command runner.
func cmdPayload(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "backfill-command-definitions" && args[0] != "backfill-run-logs" {
		return errors.New("payload: expected backfill-command-definitions or backfill-run-logs")
	}
	operation := "payload " + args[0]
	fs := flag.NewFlagSet(operation, flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state root containing master.key")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	limit := fs.Int("limit", 32, "maximum legacy rows to seal in one transaction (1..32)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s: unexpected positional argument", operation)
	}
	if *dbURL == "" {
		return fmt.Errorf("%s: missing --db (or $REACTOR_DB_URL)", operation)
	}
	if *limit < 1 || *limit > 32 {
		return fmt.Errorf("%s: --limit must be 1..32", operation)
	}
	j, closeJournal, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer closeJournal()
	hasKey, err := j.HasPayloadKey(ctx)
	if err != nil {
		return fmt.Errorf("%s: inspect journal key: %w", operation, err)
	}
	if !hasKey {
		return fmt.Errorf("%s: journal key is not initialized; start a keyed daemon before backfilling", operation)
	}
	masterHex, err := loadMasterKey(envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), *masterKeyFile, *root)
	if err != nil {
		return fmt.Errorf("%s: load master key: %w", operation, err)
	}
	master, err := decodeMasterKey(masterHex)
	if err != nil {
		return fmt.Errorf("%s: decode master key: %w", operation, err)
	}
	var previous []byte
	if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
		previous, err = decodeMasterKey(prevHex)
		if err != nil {
			return fmt.Errorf("%s: decode previous master key: %w", operation, err)
		}
	}
	if err := j.LoadPayloadEncryption(ctx, master, previous); err != nil {
		return fmt.Errorf("%s: load journal key: %w", operation, err)
	}
	var converted int
	var more bool
	switch args[0] {
	case "backfill-command-definitions":
		converted, more, err = j.BackfillLegacyCommandDefinitions(ctx, *limit)
	case "backfill-run-logs":
		converted, more, err = j.BackfillLegacyRunLogs(ctx, *limit)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	item := "command definition(s)"
	if args[0] == "backfill-run-logs" {
		item = "run log(s)"
	}
	fmt.Printf("Encrypted %d historical %s; more=%t\n", converted, item, more)
	return nil
}
