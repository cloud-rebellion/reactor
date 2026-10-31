package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/reactor/internal/migrate"
)

// Only ordinary query fixtures share these immutable schema bytes. Every test
// opens its own database file/handle and seeds its own application rows. The
// real blank/upgrade/rollback migration tests and direct Up callers are unchanged.
// Schema-defined default timestamps come from this process's one initialization;
// no application workflow, run, credential or OAuth state enters the snapshot.
var pristineTestSQLite sqliteFixtureCache

type sqliteFixtureCache struct {
	once  sync.Once
	image []byte
	err   error
}

func (c *sqliteFixtureCache) write(path string, initialize func() ([]byte, error)) error {
	c.once.Do(func() { c.image, c.err = initialize() })
	if c.err != nil {
		return c.err
	}
	// An existing file/symlink is never overwritten. Each caller owns a new path
	// under its TempDir; the shared byte slice is neither returned nor mutated.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(c.image)
	if writeErr == nil && n != len(c.image) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}

func writePristineTestSQLite(path string) error {
	return pristineTestSQLite.write(path, buildPristineSQLiteImage)
}

func buildPristineSQLiteImage() (image []byte, err error) {
	// This directory is owned by initialization, not by whichever parallel test
	// happens to arrive first. Only closed bytes survive its complete removal.
	dir, err := os.MkdirTemp("", "reactor-pristine-sqlite-server-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	path := filepath.Join(dir, "schema.db")
	silent := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(context.Background(), silent, "sqlite://"+path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if db != nil {
			err = errors.Join(err, db.Close())
		}
	}()
	var busy, logFrames, checkpointed int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return nil, err
	}
	if busy != 0 || logFrames != 0 || checkpointed != 0 {
		return nil, fmt.Errorf("pristine checkpoint incomplete: %d/%d/%d", busy, logFrames, checkpointed)
	}
	if err := db.Close(); err != nil {
		return nil, err
	}
	db = nil
	// Preserve the original persisted WAL mode, but copy no live WAL/SHM/hot
	// journal. A seed depending on a sidecar is not a valid standalone image.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pristine sidecar %s remains or is unknown: %w", suffix, err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	image, readErr := io.ReadAll(io.LimitReader(f, 16*1024*1024+1))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return nil, err
	}
	if len(image) < 100 || len(image) > 16*1024*1024 || string(image[:16]) != "SQLite format 3\x00" {
		return nil, errors.New("invalid or oversized pristine SQLite image")
	}
	return image, nil
}

func fixtureSQLiteOpen(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	})
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("fixture integrity=%q err=%v", integrity, err)
	}
	return db
}

func fixtureQueryRows(t *testing.T, db *sql.DB, query string, omitTimes bool) string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	values := []map[string]any{}
	for rows.Next() {
		raw := make([]any, len(columns))
		args := make([]any, len(columns))
		for i := range raw {
			args[i] = &raw[i]
		}
		if err := rows.Scan(args...); err != nil {
			t.Fatal(err)
		}
		item := map[string]any{}
		for i, name := range columns {
			// Only these migration bookkeeping/default-row timestamp fields
			// intentionally differ between separately migrated pristine DBs.
			if omitTimes && (name == "created_at" || name == "updated_at" || name == "tstamp") {
				continue
			}
			if b, ok := raw[i].([]byte); ok {
				item[name] = string(b)
			} else {
				item[name] = raw[i]
			}
		}
		values = append(values, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPristineSQLiteFixtureMatchesRealBlankMigration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cloned := filepath.Join(dir, "cloned.db")
	fresh := filepath.Join(dir, "fresh.db")
	if err := writePristineTestSQLite(cloned); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), "sqlite://"+fresh); err != nil {
		t.Fatal(err)
	}
	left, right := fixtureSQLiteOpen(t, cloned), fixtureSQLiteOpen(t, fresh)
	schema := "SELECT type,name,tbl_name,coalesce(sql,'') AS sql FROM sqlite_master ORDER BY type,name"
	if a, b := fixtureQueryRows(t, left, schema, false), fixtureQueryRows(t, right, schema, false); a != b {
		t.Fatal("cloned schema differs from real blank-database migration")
	}
	for table, expected := range map[string]int{"schema_meta": 2, "tenants": 1, "plans": 4} {
		var n int
		if err := left.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != expected {
			t.Fatalf("migration seed %s count=%d err=%v", table, n, err)
		}
	}
	for _, table := range []string{"schema_meta", "tenants", "plans", "goose_db_version"} {
		query := "SELECT * FROM " + table + " ORDER BY 1"
		if a, b := fixtureQueryRows(t, left, query, true), fixtureQueryRows(t, right, query, true); a != b {
			t.Fatalf("migration bookkeeping/default rows differ for %s", table)
		}
	}
	rows, err := left.Query("SELECT name FROM pragma_table_list WHERE schema='main' AND type IN ('table','virtual') AND name NOT LIKE 'sqlite_%' AND name NOT IN ('schema_meta','tenants','plans','goose_db_version') ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	if len(tables) == 0 {
		t.Fatal("pristine state assertion had no application tables")
	}
	for _, table := range tables {
		var n int
		if err := left.QueryRow("SELECT count(*) FROM \"" + strings.ReplaceAll(table, "\"", "\"\"") + "\"").Scan(&n); err != nil || n != 0 {
			t.Fatalf("pristine application table %s contains %d rows: %v", table, n, err)
		}
	}
}

func TestPristineSQLiteFixtureConcurrentClonesStayIndependent(t *testing.T) {
	t.Parallel()
	var cache sqliteFixtureCache
	var initialized atomic.Int32
	initialize := func() ([]byte, error) { initialized.Add(1); return buildPristineSQLiteImage() }
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "left.db"), filepath.Join(dir, "right.db")}
	results := make(chan error, 2)
	for _, path := range paths {
		go func(path string) { results <- cache.write(path, initialize) }(path)
	}
	for range paths {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if initialized.Load() != 1 {
		t.Fatalf("concurrent fixture initialized %d times", initialized.Load())
	}
	before := append([]byte(nil), cache.image...)
	left, right := fixtureSQLiteOpen(t, paths[0]), fixtureSQLiteOpen(t, paths[1])
	if _, err := left.Exec("INSERT INTO schema_meta(key,value) VALUES ('fixture_isolation','left')"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := right.QueryRow("SELECT count(*) FROM schema_meta WHERE key='fixture_isolation'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("test row leaked to other DB: n=%d err=%v", n, err)
	}
	third := filepath.Join(dir, "later.db")
	if err := cache.write(third, initialize); err != nil {
		t.Fatal(err)
	}
	later := fixtureSQLiteOpen(t, third)
	if err := later.QueryRow("SELECT count(*) FROM schema_meta WHERE key='fixture_isolation'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("test row leaked to later clone: n=%d err=%v", n, err)
	}
	if !reflect.DeepEqual(before, cache.image) {
		t.Fatal("caller writes mutated cached schema bytes")
	}
	if err := cache.write(paths[0], initialize); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing clone was not refused: %v", err)
	}
}

func TestPristineSQLiteFixtureCachesInitializationFailure(t *testing.T) {
	t.Parallel()
	var cache sqliteFixtureCache
	var initialized atomic.Int32
	expected := errors.New("fixture initialization failed")
	initialize := func() ([]byte, error) { initialized.Add(1); return nil, expected }
	for _, name := range []string{"first.db", "second.db"} {
		path := filepath.Join(t.TempDir(), name)
		if err := cache.write(path, initialize); !errors.Is(err, expected) {
			t.Fatalf("initialization failure not preserved: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed fixture wrote a DB: %v", err)
		}
	}
	if initialized.Load() != 1 {
		t.Fatalf("failed initializer retried %d times", initialized.Load())
	}
}
