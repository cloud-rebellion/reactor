package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// Local Postgres admission and distributed claiming share the tenant policy
// lock. The admission transaction must use READ COMMITTED so its counter sees
// work that committed while it waited, regardless of server defaults.
func TestPostgresWorkflowAdmissionUsesFreshSnapshotAndOneTenantSlot(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL admission isolation contract")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migrate.Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("test URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := "admission-cap-" + suffix
	wfIDs := []string{"wf_admission_left_" + suffix, "wf_admission_right_" + suffix}
	runIDs := []string{"run_admission_left_" + suffix, "run_admission_right_" + suffix}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM runs WHERE id IN ($1,$2)`, runIDs[0], runIDs[1])
		_, _ = db.ExecContext(context.Background(), `DELETE FROM workflows WHERE id IN ($1,$2)`, wfIDs[0], wfIDs[1])
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	}()
	if err := j.UpsertTenant(ctx, Tenant{TenantID: tenantID, MaxConcurrentRuns: 1}); err != nil {
		t.Fatal(err)
	}
	const artifact = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	for _, wfID := range wfIDs {
		if err := j.CreateWorkflowInTenantWithArtifact(ctx, wfID, wfID+"-slug", "h", "0.1.0", artifact, json.RawMessage(`{}`), tenantID); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := j.beginWorkflowAdmissionTx(ctx, wfIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	var isolation string
	if err := tx.QueryRowContext(ctx, `SHOW transaction_isolation`).Scan(&isolation); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if isolation != "read committed" {
		t.Fatalf("workflow admission isolation = %q, want read committed", isolation)
	}

	start := make(chan struct{})
	done := make(chan error, 2)
	for i := range wfIDs {
		go func(runID, wfID string) {
			<-start
			done <- j.CreateRunPinnedIfEnabled(ctx, runID, wfID, "manual", json.RawMessage(`{}`), 1, artifact)
		}(runIDs[i], wfIDs[i])
	}
	close(start)
	succeeded, refused := 0, 0
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				succeeded++
				continue
			}
			var quota *QuotaError
			if !errors.As(err, &quota) || quota.TenantID != tenantID {
				t.Fatalf("concurrent admission = %v, want tenant concurrency refusal", err)
			}
			refused++
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("concurrent admission: succeeded=%d refused=%d, want 1/1", succeeded, refused)
	}
}
