package migrate

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckCurrentNeverMigratesWorkerDatabase(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rawURL := "sqlite://" + filepath.Join(t.TempDir(), "worker.db")
	db, engine, err := Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := CheckCurrent(ctx, db, engine); err == nil || !strings.Contains(err.Error(), "run reactor migrate") {
		t.Fatalf("unmigrated worker database check = %v", err)
	}
	var tables int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'goose_db_version'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("worker check created version table: count=%d err=%v", tables, err)
	}
	if err := Up(ctx, log, rawURL); err != nil {
		t.Fatal(err)
	}
	if err := CheckCurrent(ctx, db, engine); err != nil {
		t.Fatalf("current schema rejected: %v", err)
	}
	var latest int64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version_id) FROM goose_db_version WHERE is_applied = 1`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (?, 0)`, latest); err != nil {
		t.Fatal(err)
	}
	if err := CheckCurrent(ctx, db, engine); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("rolled-back schema version accepted: %v", err)
	}
}

func TestCheckCurrentRejectsMissingEarlierMigration(t *testing.T) {
	ctx := context.Background()
	rawURL := "sqlite://" + filepath.Join(t.TempDir(), "gap.db")
	if err := Up(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), rawURL); err != nil {
		t.Fatal(err)
	}
	db, engine, err := Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `UPDATE goose_db_version SET is_applied = 0 WHERE version_id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := CheckCurrent(ctx, db, engine); err == nil || !strings.Contains(err.Error(), "version 1 is not applied") {
		t.Fatalf("migration history gap accepted: %v", err)
	}
}
