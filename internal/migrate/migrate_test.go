package migrate

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngineFromURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		url     string
		want    Engine
		wantErr bool
	}{
		{"sqlite scheme", "sqlite://./test.db", EngineSQLite, false},
		{"sqlite3 scheme", "sqlite3://./test.db", EngineSQLite, false},
		{"file scheme", "file:./test.db", EngineSQLite, false},
		{"postgres scheme", "postgres://u:p@h/d", EnginePostgres, false},
		{"postgresql scheme", "postgresql://u:p@h/d", EnginePostgres, false},
		{"empty url", "", "", true},
		{"unsupported scheme", "mysql://u:p@h/d", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EngineFromURL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got engine %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPostgresPoolFromEnv(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		vars    map[string]string
		want    postgresPoolConfig
		wantErr string
	}{
		{name: "defaults", want: postgresPoolConfig{maxOpen: 8, maxIdle: 4}},
		{name: "custom", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "12", "REACTOR_DB_MAX_IDLE_CONNS": "6"}, want: postgresPoolConfig{maxOpen: 12, maxIdle: 6}},
		{name: "small open clamps default idle", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "2"}, want: postgresPoolConfig{maxOpen: 2, maxIdle: 2}},
		{name: "no idle connections", vars: map[string]string{"REACTOR_DB_MAX_IDLE_CONNS": "0"}, want: postgresPoolConfig{maxOpen: 8, maxIdle: 0}},
		{name: "largest allowed open", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "256"}, want: postgresPoolConfig{maxOpen: 256, maxIdle: 4}},
		{name: "unlimited open refused", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "0"}, wantErr: "REACTOR_DB_MAX_OPEN_CONNS"},
		{name: "one connection refused", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "1"}, wantErr: "REACTOR_DB_MAX_OPEN_CONNS"},
		{name: "excess open refused", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "257"}, wantErr: "REACTOR_DB_MAX_OPEN_CONNS"},
		{name: "invalid open refused", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "many"}, wantErr: "REACTOR_DB_MAX_OPEN_CONNS"},
		{name: "empty open refused", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": ""}, wantErr: "REACTOR_DB_MAX_OPEN_CONNS"},
		{name: "negative idle refused", vars: map[string]string{"REACTOR_DB_MAX_IDLE_CONNS": "-1"}, wantErr: "REACTOR_DB_MAX_IDLE_CONNS"},
		{name: "idle exceeds open refused", vars: map[string]string{"REACTOR_DB_MAX_OPEN_CONNS": "2", "REACTOR_DB_MAX_IDLE_CONNS": "3"}, wantErr: "REACTOR_DB_MAX_IDLE_CONNS"},
		{name: "invalid idle refused", vars: map[string]string{"REACTOR_DB_MAX_IDLE_CONNS": "many"}, wantErr: "REACTOR_DB_MAX_IDLE_CONNS"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := postgresPoolFromEnv(func(name string) (string, bool) {
				v, ok := tc.vars[name]
				return v, ok
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || cfg != tc.want {
				t.Fatalf("pool = %+v, err = %v; want %+v", cfg, err, tc.want)
			}
		})
	}
}

func TestConfigurePostgresPoolBoundsConnections(t *testing.T) {
	t.Parallel()
	// Pool configuration uses database/sql, independently of the driver. Use a
	// local SQLite connection to verify the limits without needing Postgres.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	configurePostgresPool(db, postgresPoolConfig{maxOpen: 2, maxIdle: 1})
	if got := db.Stats().MaxOpenConnections; got != 2 {
		t.Fatalf("max open = %d, want 2", got)
	}
	first, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.Conn(context.Background())
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if got := db.Stats().Idle; got != 1 {
		t.Fatalf("idle connections = %d, want 1", got)
	}
}

func TestOpenRejectsInvalidPostgresPoolBeforeDial(t *testing.T) {
	t.Setenv("REACTOR_DB_MAX_OPEN_CONNS", "0")
	db, engine, err := Open("postgres://user:password@127.0.0.1:1/reactor")
	if db != nil || engine != "" || err == nil || !strings.Contains(err.Error(), "REACTOR_DB_MAX_OPEN_CONNS") {
		t.Fatalf("Open = db:%v engine:%q err:%v; want pool validation error before dial", db, engine, err)
	}
}

func TestSQLitePoolIgnoresPostgresSettings(t *testing.T) {
	t.Setenv("REACTOR_DB_MAX_OPEN_CONNS", "0")
	db, engine, err := Open("sqlite://" + filepath.Join(t.TempDir(), "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != EngineSQLite || db.Stats().MaxOpenConnections != 4 {
		t.Fatalf("engine = %q, max open = %d; want sqlite with 4", engine, db.Stats().MaxOpenConnections)
	}
}

func TestUpSQLite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	url := "sqlite://" + dbPath

	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if err := Up(context.Background(), log, url); err != nil {
		t.Fatalf("Up: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var version, engine string
	if err := db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'schema_version'`).Scan(&version); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version != "1" {
		t.Fatalf("schema_version = %q, want %q", version, "1")
	}
	if err := db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'engine'`).Scan(&engine); err != nil {
		t.Fatalf("query engine: %v", err)
	}
	if engine != "sqlite" {
		t.Fatalf("engine = %q, want %q", engine, "sqlite")
	}

	// Idempotency: second Up should be a no-op (no pending migrations).
	if err := Up(context.Background(), log, url); err != nil {
		t.Fatalf("second Up: %v", err)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
