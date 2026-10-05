package journal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestPostgresArtifactPublicationSkipsLockedAndFencesTenant(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL artifact publication test")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must be PostgreSQL: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("artifact_publications_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	scopedURL := u.String()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), scopedURL); err != nil {
		t.Fatal(err)
	}
	db, _, err := migrate.Open(scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j := New(db, EnginePostgres)
	digest := strings.Repeat("a", 64)
	seedArtifactPublicationWorkflow(t, j, "wf_pg_pub", "pg-publication", "pg-tenant", digest)
	publication, err := j.EnqueueArtifactPublication(ctx, "pg-tenant", "wf_pg_pub", 1, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.GetArtifactPublicationForTenant(ctx, publication.ID, "foreign"); err != ErrNotFound {
		t.Fatalf("foreign tenant receipt = %v", err)
	}
	locker, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback()
	var lockedID string
	if err := locker.QueryRowContext(ctx, `SELECT id FROM artifact_publications WHERE id = $1 FOR UPDATE`, publication.ID).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	claimCtx, claimCancel := context.WithTimeout(ctx, 2*time.Second)
	defer claimCancel()
	claimed, err := j.ClaimArtifactPublications(claimCtx, 1, time.Minute)
	if err != nil || len(claimed) != 0 {
		t.Fatalf("SKIP LOCKED claim = %+v, %v", claimed, err)
	}
	if err := locker.Rollback(); err != nil {
		t.Fatal(err)
	}
	claimed, err = j.ClaimArtifactPublications(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].ID != publication.ID {
		t.Fatalf("unlocked claim = %+v, %v", claimed, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE artifact_publications SET attempts = $1 WHERE id = $2`, MaxArtifactPublicationAttempts, publication.ID); err != nil {
		t.Fatal(err)
	}
	if err := j.FailArtifactPublication(ctx, publication.ID, claimed[0].ClaimToken, "copy_failed"); err != nil {
		t.Fatal(err)
	}
	requeued, err := j.RequeueFailedArtifactPublication(ctx, "pg-tenant", publication.ID, digest)
	if err != nil || requeued.ID != publication.ID || requeued.Status != ArtifactPublicationPending || requeued.Attempts != 0 {
		t.Fatalf("Postgres requeue = %+v, %v", requeued, err)
	}
	claimed, err = j.ClaimArtifactPublications(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 1 {
		t.Fatalf("Postgres recovered claim = %+v, %v", claimed, err)
	}
	if err := j.CompleteArtifactPublication(ctx, publication.ID, claimed[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
}
