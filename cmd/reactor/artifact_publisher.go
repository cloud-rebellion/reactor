package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bright-interaction/reactor/internal/artifactmirror"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

const artifactPublicationDAGLimit = 1 << 20

// cmdArtifactPublisher is a separate, least-privilege fleet role. It needs
// Postgres, read access to the durable authoring workflows tree, and write
// access to the worker artifact tree; it needs no vault key or HTTP listener.
func cmdArtifactPublisher(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("artifact-publisher", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "shared Postgres database URL")
	sourceRoot := fs.String("source-root", os.Getenv("REACTOR_PUBLISHER_SOURCE_ROOT"), "absolute state root containing the durable authoring workflows/ tree")
	destinationRoot := fs.String("destination-root", os.Getenv("REACTOR_PUBLISHER_DESTINATION_ROOT"), "absolute writable state root backed by the worker artifact volume")
	poll := fs.Duration("poll-interval", 2*time.Second, "idle queue poll interval")
	lease := fs.Duration("lease-ttl", 5*time.Minute, "durable publication claim lease, renewed during copying")
	once := fs.Bool("once", false, "process at most one pending request, then exit")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if !isPostgresURL(*dbURL) {
		return errors.New("artifact-publisher: a postgres:// database is required")
	}
	if !filepath.IsAbs(*sourceRoot) || !filepath.IsAbs(*destinationRoot) {
		return errors.New("artifact-publisher: absolute --source-root and --destination-root are required")
	}
	if *poll < 100*time.Millisecond || *poll > time.Minute {
		return errors.New("artifact-publisher: --poll-interval must be between 100ms and 1m")
	}
	if *lease < 5*time.Second || *lease > 30*time.Minute {
		return errors.New("artifact-publisher: --lease-ttl must be between 5s and 30m")
	}
	db, engine, err := migrate.Open(*dbURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		return errors.New("artifact-publisher: PostgreSQL is required")
	}
	if err := migrate.CheckCurrent(ctx, db, engine); err != nil {
		return fmt.Errorf("artifact-publisher: schema is not current: %w", err)
	}
	if err := requireArtifactPublisherRoots(*sourceRoot, *destinationRoot); err != nil {
		return err
	}
	j := journal.New(db, journal.EnginePostgres)
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		claimed, err := j.ClaimArtifactPublications(runCtx, 1, *lease)
		if err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return fmt.Errorf("artifact-publisher: claim request: %w", err)
		}
		if len(claimed) > 0 {
			p := claimed[0]
			if code, err := processArtifactPublication(runCtx, j, *sourceRoot, *destinationRoot, p, *lease); err != nil {
				// The durable row contains only this allowlisted code. Host paths,
				// source bytes, and any database credentials stay out of logs.
				log.Warn("artifact publication incomplete", "publication_id", p.ID, "failure_code", code)
				if *once {
					return fmt.Errorf("artifact-publisher: publication %s incomplete: %s", p.ID, code)
				}
			} else {
				log.Info("artifact publication verified", "publication_id", p.ID, "workflow_id", p.WorkflowID, "version", p.Version)
			}
			if *once {
				return nil
			}
			continue
		}
		if *once {
			return nil
		}
		select {
		case <-runCtx.Done():
			return nil
		case <-time.After(*poll):
		}
	}
}

func requireArtifactPublisherRoots(sourceRoot, destinationRoot string) error {
	for _, root := range []string{sourceRoot, destinationRoot} {
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("artifact-publisher: source and destination roots must be existing directories, not symlinks")
		}
	}
	sourceReal, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return errors.New("artifact-publisher: source root cannot be resolved")
	}
	destinationReal, err := filepath.EvalSymlinks(destinationRoot)
	if err != nil {
		return errors.New("artifact-publisher: destination root cannot be resolved")
	}
	if artifactPublisherPathWithin(sourceReal, destinationReal) || artifactPublisherPathWithin(destinationReal, sourceReal) {
		return errors.New("artifact-publisher: source and destination roots must not overlap")
	}
	return nil
}

func artifactPublisherPathWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// processArtifactPublication always verifies the journal's exact tenant,
// workflow, version, and digest before copying. An uncertain acknowledgment
// leaves the claim for an idempotent retry; it never marks bytes published.
func processArtifactPublication(ctx context.Context, j *journal.Journal, sourceRoot, destinationRoot string, p journal.ArtifactPublication, lease time.Duration) (string, error) {
	if p.ID == "" || p.ClaimToken == "" || p.TenantID == "" || p.WorkflowID == "" || p.Slug == "" || p.Version < 1 {
		return "configuration_error", errors.New("artifact publication claim is incomplete")
	}
	copyCtx, cancelCopy := context.WithCancel(ctx)
	defer cancelCopy()
	renewDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(lease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-copyCtx.Done():
				renewDone <- nil
				return
			case <-ticker.C:
				renewCtx, cancel := context.WithTimeout(copyCtx, min(lease/3, 10*time.Second))
				err := j.RenewArtifactPublicationClaim(renewCtx, p.ID, p.ClaimToken, lease)
				cancel()
				if err != nil {
					cancelCopy()
					renewDone <- err
					return
				}
			}
		}
	}()
	code, publishErr := publishClaimedArtifact(copyCtx, j, sourceRoot, destinationRoot, p)
	cancelCopy()
	renewErr := <-renewDone
	if renewErr != nil {
		return "lease_expired", fmt.Errorf("artifact publication claim renewal failed: %w", renewErr)
	}
	if ctx.Err() != nil {
		return "lease_expired", ctx.Err()
	}
	ackCtx, cancelAck := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancelAck()
	if publishErr == nil {
		if err := j.CompleteArtifactPublication(ackCtx, p.ID, p.ClaimToken); err != nil {
			return "lease_expired", fmt.Errorf("artifact publication acknowledgement failed: %w", err)
		}
		return "", nil
	}
	if err := j.FailArtifactPublication(ackCtx, p.ID, p.ClaimToken, code); err != nil {
		return "lease_expired", fmt.Errorf("artifact publication failure acknowledgement failed: %w", err)
	}
	return code, publishErr
}

func publishClaimedArtifact(ctx context.Context, j *journal.Journal, sourceRoot, destinationRoot string, p journal.ArtifactPublication) (string, error) {
	owner, err := j.WorkflowTenant(ctx, p.WorkflowID)
	if err != nil || owner != p.TenantID {
		return "source_unverified", errors.New("artifact publication workflow tenant does not match claim")
	}
	slug, err := j.WorkflowSlugByID(ctx, p.WorkflowID)
	if err != nil || slug != p.Slug {
		return "source_unverified", errors.New("artifact publication workflow slug does not match claim")
	}
	v, err := j.WorkflowVersionAtBounded(ctx, p.WorkflowID, p.Version, artifactPublicationDAGLimit)
	if err != nil {
		return "source_unavailable", errors.New("artifact publication version is unavailable")
	}
	if v.WorkflowID != p.WorkflowID || v.Version != p.Version || v.DAGTruncated || v.ArtifactSHA256 != p.ArtifactSHA256 || v.SourceProofVersion != 2 {
		return "source_unverified", errors.New("artifact publication exact version proof does not match claim")
	}
	proof := workflowproof.CheckVersionForTenant(sourceRoot, p.Slug, p.TenantID, v)
	if proof.Status != "verified" {
		code := "source_unverified"
		if proof.Status == "unavailable" {
			code = "source_unavailable"
		}
		return code, errors.New("artifact publication source proof failed")
	}
	if err := requireArtifactPublisherRoots(sourceRoot, destinationRoot); err != nil {
		return "destination_unavailable", err
	}
	if _, err := artifactmirror.MirrorVersion(ctx, sourceRoot, destinationRoot, p.Slug, p.TenantID, v); err != nil {
		return "copy_failed", errors.New("artifact publication copy or destination verification failed")
	}
	if proof := workflowproof.CheckVersionForTenant(destinationRoot, p.Slug, p.TenantID, v); proof.Status != "verified" {
		return "proof_failed", errors.New("artifact publication destination proof failed")
	}
	return "", nil
}
