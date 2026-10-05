package journal

import (
	"context"
	"encoding/json"
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

func postgresNotificationReceiptJournal(t *testing.T) *Journal {
	t.Helper()
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL for PostgreSQL notification receipt parity")
	}
	engine, err := migrate.EngineFromURL(rawURL)
	if err != nil || engine != migrate.EnginePostgres {
		t.Fatalf("test URL must use PostgreSQL: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(strings.ToLower(strings.Trim(u.Path, "/")), "test") {
		t.Fatal("PostgreSQL test database name must contain test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	base, _, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	schema := fmt.Sprintf("notification_receipts_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
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
	t.Cleanup(func() { db.Close() })
	j := New(db, EnginePostgres)
	if err := j.CreateWorkflow(ctx, "wf_receipts_pg", "receipts-pg", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_receipts_pg", "wf_receipts_pg", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	return j
}

func TestPostgresNotificationDeliverySnapshotAndPerChannelRetry(t *testing.T) {
	j := postgresNotificationReceiptJournal(t)
	testNotificationDeliverySnapshotAndPerChannelRetry(t, j, "run_receipts_pg", "wf_receipts_pg")
}

func TestPostgresNotificationDeliverySameStatusRedrive(t *testing.T) {
	j := postgresNotificationReceiptJournal(t)
	testNotificationDeliveryRedriveGenerationAndDeletedChannel(t, j, "run_receipts_pg", "wf_receipts_pg")
}

func TestPostgresNotificationDeliveryEmptySnapshot(t *testing.T) {
	j := postgresNotificationReceiptJournal(t)
	testNotificationDeliveryEmptySnapshotAllowsTerminalAck(t, j, "run_receipts_pg", "wf_receipts_pg")
}

func TestPostgresNotificationDeliveryTenantChangeAfterSnapshot(t *testing.T) {
	j := postgresNotificationReceiptJournal(t)
	testNotificationDeliveryTenantChangeAfterSnapshotFailsClosed(t, j, "run_receipts_pg", "wf_receipts_pg")
}
