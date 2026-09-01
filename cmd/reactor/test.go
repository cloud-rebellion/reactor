package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

// cmdTest replays a recorded run through the supervisor in Mode="replay"
// and asserts no divergence. The supervisor's replay path returns
// ErrReplayDivergence on any step_start that lacks a cached output, so
// a green test means: the workflow's control flow + Step calls are
// deterministic given the recorded inputs.
//
//	reactor test <slug> --against-run <run-id> --db <url> --root <dir>
//	reactor test <slug> --latest                --db <url> --root <dir>
//
// When --latest is set, picks the most recent succeeded run for the
// slug. This is the AI-friendly path: ship a workflow, run it once
// against real inputs, then `reactor test <slug> --latest` proves the
// closure outputs are journaled + replay-safe.
//
// Out of scope for v1: synthetic input mode (fresh run → replay)
// because that requires a real subprocess spawn against unrelated
// state. Operators who want it can chain `reactor dispatch` + this
// command manually.
func cmdTest(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", defaultRoot(), "Reactor state root (workflow binaries live under <root>/workflows/)")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file)")
	againstRun := fs.String("against-run", "", "run id to replay (mutually exclusive with --latest)")
	latest := fs.Bool("latest", false, "pick the most recent succeeded run for the slug")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("test: missing <slug>")
	}
	slug := fs.Arg(0)
	if *dbURL == "" {
		return errors.New("test: missing --db (or $REACTOR_DB_URL)")
	}
	if *root == "" {
		return errors.New("test: missing --root (and HOME unset)")
	}
	if *againstRun == "" && !*latest {
		return errors.New("test: pass --against-run <id> or --latest")
	}
	if *againstRun != "" && *latest {
		return errors.New("test: --against-run and --latest are mutually exclusive")
	}

	masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
	if err != nil {
		return err
	}

	j, jClose, err := openJournal(*dbURL)
	if err != nil {
		return err
	}
	defer jClose()

	wfID, err := defaultTenantWorkflowID(ctx, j, slug)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return fmt.Errorf("test: workflow %q not registered", slug)
		}
		return err
	}

	runID := *againstRun
	if *latest {
		runID, err = pickLatestRunForSlug(ctx, j, wfID)
		if err != nil {
			return err
		}
		fmt.Printf("test: picked latest succeeded run %s for %s\n", runID, slug)
	}

	run, err := j.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("test: get run %s: %w", runID, err)
	}
	if run.WorkflowID != wfID {
		return fmt.Errorf("test: run %s belongs to workflow %s, not %s", runID, run.WorkflowID, slug)
	}

	store, vaultCloser, err := openVaultStore(*dbURL, masterHex)
	if err != nil {
		return err
	}
	defer vaultCloser()

	reg := registry.New(filepath.Join(*root, "workflows"))
	candidate, err := reg.BuildArtifact(slug)
	if err != nil {
		return fmt.Errorf("test: immutable build candidate lookup: %w (run `reactor workflow build` first)", err)
	}
	binaryPath := candidate.Path

	// Read the run's original input so the replay subprocess sees the
	// same payload the original run did. Without this the workflow
	// body might branch differently and a divergence-after-Hello fires
	// even though the closure outputs would have been identical.
	steps, err := j.ListSteps(ctx, runID)
	if err != nil {
		return fmt.Errorf("test: list steps: %w", err)
	}
	if len(steps) == 0 {
		return fmt.Errorf("test: run %s has no steps; nothing to replay", runID)
	}

	fmt.Printf("test: replaying %s (workflow=%s, %d step row(s) in journal)\n", runID, slug, len(steps))

	// Replay subprocess. Mode="replay" makes the supervisor refuse any
	// step_start that lacks a cached output, surfacing divergence as
	// ErrReplayDivergence rather than silently re-executing side
	// effects.
	signKey, _ := decodeMasterKey(masterHex)
	sup := supervisor.Supervisor{
		BinaryPath:       binaryPath,
		WorkflowSlug:     slug,
		RunID:            runID,
		Mode:             "replay",
		Journal:          j,
		Vault:            store,
		Log:              log,
		SignalSigningKey: signKey,
		// Reuse the original trigger meta as the replay input so the
		// workflow body branches the same way it did originally.
		Input: run.TriggerMeta,
	}

	start := time.Now()
	status, runErr := sup.Run(ctx)
	elapsed := time.Since(start)

	if runErr != nil {
		if errors.Is(runErr, supervisor.ErrReplayDivergence) {
			fmt.Printf("\nFAIL: replay divergence after %s\n  status=%s\n  err=%v\n\nThe workflow tried to call a Step that has no cached output in the journal. That means either:\n  - control flow branched differently on replay (use reactor.SideEffect for non-deterministic decisions)\n  - the workflow added a new Step since the original run\n  - a Step name changed\n", elapsed, status, runErr)
			return fmt.Errorf("test: divergence")
		}
		fmt.Printf("\nFAIL: replay errored after %s\n  status=%s\n  err=%v\n", elapsed, status, runErr)
		return fmt.Errorf("test: replay errored")
	}
	if status != "succeeded" && status != run.Status {
		fmt.Printf("\nFAIL: replay terminal status mismatch\n  original=%s\n  replay=%s\n", run.Status, status)
		return fmt.Errorf("test: status mismatch")
	}
	fmt.Printf("\nPASS: replay green in %s (%d step(s) cache-hit, no divergence)\n", elapsed, len(steps))
	return nil
}

// pickLatestRunForSlug returns the most recent succeeded run id for
// the workflow. Falls back to "succeeded or failed_dlq" if no succeeded
// run exists; replay against a failed run still proves the
// determinism property up to the failure point.
func pickLatestRunForSlug(ctx context.Context, j *journal.Journal, wfID string) (string, error) {
	for _, st := range []string{"succeeded", "failed_dlq", "failed"} {
		runs, err := j.ListRuns(ctx, journal.RunFilter{
			WorkflowID: wfID,
			Status:     st,
			Limit:      1,
		})
		if err != nil {
			return "", err
		}
		if len(runs) > 0 {
			return runs[0].ID, nil
		}
	}
	return "", errors.New("test: no terminal runs found for this workflow; trigger one first")
}
