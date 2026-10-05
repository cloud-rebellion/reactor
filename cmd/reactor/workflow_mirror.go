package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bright-interaction/reactor/internal/artifactmirror"
)

// cmdWorkflowMirror is an explicit, exact-version publication step for a
// separate publisher with write access to the worker artifact volume. Serving
// daemons and workers can keep that volume mounted read-only.
func cmdWorkflowMirror(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("workflow mirror", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL")
	root := fs.String("root", "", "source Reactor state root")
	destinationRoot := fs.String("destination-root", "", "existing writable state root mounted from the worker artifact volume")
	slug := fs.String("slug", "", "workflow slug")
	tenant := fs.String("tenant", "", "exact workflow tenant")
	versionNumber := fs.Int("version", 0, "exact immutable workflow version")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if strings.TrimSpace(*dbURL) == "" || strings.TrimSpace(*slug) == "" || strings.TrimSpace(*tenant) == "" || *versionNumber < 1 || !filepath.IsAbs(*root) || !filepath.IsAbs(*destinationRoot) {
		return errors.New("workflow mirror: --db, --slug, --tenant, --version (>0), and absolute --root and --destination-root are required")
	}
	j, closer, err := openJournalForCLI(*dbURL)
	if err != nil {
		return err
	}
	defer closer()
	id, err := j.WorkflowIDBySlugInTenant(ctx, *slug, *tenant)
	if err != nil {
		return fmt.Errorf("workflow mirror: resolve tenant workflow: %w", err)
	}
	version, err := j.WorkflowVersionAtBounded(ctx, id, *versionNumber, 1<<20)
	if err != nil {
		return fmt.Errorf("workflow mirror: resolve exact version: %w", err)
	}
	if version.DAGTruncated {
		return errors.New("workflow mirror: version DAG exceeds proof limit")
	}
	if version.WorkflowID != id || version.Version != *versionNumber {
		return errors.New("workflow mirror: version identity changed during lookup")
	}
	path, err := artifactmirror.MirrorVersion(ctx, *root, *destinationRoot, *slug, *tenant, version)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "mirrored tenant=%s workflow=%s version=%d artifact=%s path=%s\n", *tenant, *slug, version.Version, version.ArtifactSHA256, path)
	return nil
}
