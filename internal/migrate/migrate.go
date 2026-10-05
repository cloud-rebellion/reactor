// Package migrate runs database migrations from embedded FS using goose.
// SQLite and Postgres migrations live in separate directories so each can
// use idiomatic SQL for its engine. The driver is selected from the URL scheme.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pressly/goose/v3"

	dbpkg "github.com/bright-interaction/reactor/internal/db"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// gooseMu serializes goose calls because goose v3 keeps base FS, dialect,
// and logger in package globals. Concurrent migrate.Up calls (e.g. from
// parallel tests) race on those globals; the lock costs only contention
// during migration which is run-once-at-startup in production.
var gooseMu sync.Mutex

// Engine reports which dialect this URL targets.
type Engine string

const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"

	// A distributed serve process holds one dedicated advisory-lock connection.
	// Leave at least one other connection for the journal and HTTP requests.
	postgresDefaultMaxOpenConns = 8
	postgresDefaultMaxIdleConns = 4
	postgresMaxOpenConnsLimit   = 256
)

type postgresPoolConfig struct {
	maxOpen int
	maxIdle int
}

// postgresPoolFromEnv validates limits before opening a network connection.
// database/sql treats maxOpen=0 as unlimited and silently clamps maxIdle, so
// reject those unsafe/misleading operator values instead of passing them on.
func postgresPoolFromEnv(lookupEnv func(string) (string, bool)) (postgresPoolConfig, error) {
	cfg := postgresPoolConfig{
		maxOpen: postgresDefaultMaxOpenConns,
		maxIdle: postgresDefaultMaxIdleConns,
	}
	if raw, ok := lookupEnv("REACTOR_DB_MAX_OPEN_CONNS"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < 2 || n > postgresMaxOpenConnsLimit {
			return postgresPoolConfig{}, fmt.Errorf("REACTOR_DB_MAX_OPEN_CONNS must be an integer between 2 and %d", postgresMaxOpenConnsLimit)
		}
		cfg.maxOpen = n
		if cfg.maxIdle > n {
			cfg.maxIdle = n
		}
	}
	if raw, ok := lookupEnv("REACTOR_DB_MAX_IDLE_CONNS"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < 0 || n > cfg.maxOpen {
			return postgresPoolConfig{}, fmt.Errorf("REACTOR_DB_MAX_IDLE_CONNS must be an integer between 0 and REACTOR_DB_MAX_OPEN_CONNS (%d)", cfg.maxOpen)
		}
		cfg.maxIdle = n
	}
	return cfg, nil
}

// EngineFromURL infers the engine from a database URL.
//
//	sqlite://./reactor.db
//	sqlite:reactor.db
//	postgres://user:pass@host/db
//	postgresql://user:pass@host/db
func EngineFromURL(rawURL string) (Engine, error) {
	if rawURL == "" {
		return "", errors.New("database URL is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse db url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "sqlite", "sqlite3", "file":
		return EngineSQLite, nil
	case "postgres", "postgresql":
		return EnginePostgres, nil
	default:
		return "", fmt.Errorf("unsupported db scheme %q (want sqlite:// or postgres://)", u.Scheme)
	}
}

// Open returns a *sql.DB ready for migration. Caller closes.
func Open(rawURL string) (*sql.DB, Engine, error) {
	engine, err := EngineFromURL(rawURL)
	if err != nil {
		return nil, "", err
	}
	var pgPool postgresPoolConfig
	if engine == EnginePostgres {
		pgPool, err = postgresPoolFromEnv(os.LookupEnv)
		if err != nil {
			return nil, "", err
		}
	}
	// driverName is the stdlib database/sql registration string. modernc's
	// sqlite registers as "sqlite"; pgx's stdlib bridge registers as "pgx",
	// not "postgres". Using the engine string verbatim used to fail at
	// sql.Open with `unknown driver "postgres"`.
	driver := "sqlite"
	if engine == EnginePostgres {
		driver = "pgx"
	}
	dsn := rawURL
	if engine == EngineSQLite {
		// modernc.org/sqlite expects a path, not a URL.
		// Strip the scheme and any leading // .
		dsn = strings.TrimPrefix(rawURL, "sqlite://")
		dsn = strings.TrimPrefix(dsn, "sqlite:")
		dsn = strings.TrimPrefix(dsn, "file:")
		dsn = sqliteDSNWithPragmas(dsn)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, "", fmt.Errorf("open db: %w", err)
	}
	if engine == EngineSQLite {
		// WAL lets one writer proceed alongside readers, and busy_timeout
		// makes a writer that loses the race wait (up to 5s) instead of
		// erroring out with SQLITE_BUSY immediately. Without this, two
		// concurrent writers (dashboard + scheduler + dispatcher all share
		// one *sql.DB) collide on the first overlap and a busy
		// MarkRunFinished can leave a run stuck "running" forever. Cap the
		// pool so a held write transaction can't starve the next query.
		db.SetMaxOpenConns(4)
		db.SetConnMaxIdleTime(5 * time.Minute)
	} else {
		configurePostgresPool(db, pgPool)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, "", fmt.Errorf("ping db: %w", err)
	}
	return db, engine, nil
}

func configurePostgresPool(db *sql.DB, cfg postgresPoolConfig) {
	db.SetMaxOpenConns(cfg.maxOpen)
	db.SetMaxIdleConns(cfg.maxIdle)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
}

// sqliteDSNWithPragmas appends the durability + concurrency pragmas every
// SQLite connection in the pool should open with. modernc.org/sqlite reads
// `_pragma=` query parameters and applies them per connection, so WAL +
// busy_timeout + foreign_keys are guaranteed on every handle, not just the
// first. Existing query params on the DSN are preserved.
func sqliteDSNWithPragmas(dsn string) string {
	pragmas := []string{
		"_pragma=busy_timeout(5000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + strings.Join(pragmas, "&")
}

// Up applies all pending migrations against the given URL.
func Up(ctx context.Context, log *slog.Logger, rawURL string) error {
	return upTo(ctx, log, rawURL, maxVersion)
}

// maxVersion is goose's "apply everything" sentinel, the same value its own
// Up uses internally.
const maxVersion int64 = int64(^uint64(0) >> 1)

// upTo applies migrations up to and including version. Tests use it to stage a
// database at an intermediate revision, populate it, and then step forward, which
// is the only way to prove a table-rebuild migration preserves existing rows: a
// from-scratch schema has nothing to lose.
func upTo(ctx context.Context, log *slog.Logger, rawURL string, version int64) error {
	db, engine, err := Open(rawURL)
	if err != nil {
		return err
	}
	defer db.Close()

	sub, err := fs.Sub(dbpkg.Migrations, "migrations/"+string(engine))
	if err != nil {
		return fmt.Errorf("locate migrations for %s: %w", engine, err)
	}

	gooseMu.Lock()
	defer gooseMu.Unlock()

	goose.SetBaseFS(sub)
	goose.SetLogger(gooseSlogAdapter{log: log})

	dialect := string(engine)
	if engine == EngineSQLite {
		dialect = "sqlite3"
	}
	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("set dialect: %w", err)
	}
	return goose.UpToContext(ctx, db, ".", version)
}

// gooseSlogAdapter bridges goose's stdlib-style logger interface to slog.
type gooseSlogAdapter struct{ log *slog.Logger }

func (a gooseSlogAdapter) Fatalf(format string, v ...interface{}) {
	a.log.Error(fmt.Sprintf(format, v...))
}
func (a gooseSlogAdapter) Printf(format string, v ...interface{}) {
	a.log.Info(strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
}
