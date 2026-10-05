package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
)

// CheckCurrent verifies that an already migrated database has every schema
// version embedded in this binary. It never applies migrations or creates the
// goose version table: scaled workers must not need DDL permission or race a
// serving daemon through schema changes when they start.
func CheckCurrent(ctx context.Context, db *sql.DB, engine Engine) error {
	if db == nil {
		return fmt.Errorf("migration check: database is required")
	}
	if engine != EngineSQLite && engine != EnginePostgres {
		return fmt.Errorf("migration check: unsupported engine %q", engine)
	}
	entries, err := fs.ReadDir(dbpkg.Migrations, "migrations/"+string(engine))
	if err != nil {
		return fmt.Errorf("migration check: embedded versions: %w", err)
	}
	want := make(map[int64]struct{}, len(entries))
	var latest int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		version, parseErr := strconv.ParseInt(prefix, 10, 64)
		if !ok || parseErr != nil || version <= 0 {
			return fmt.Errorf("migration check: invalid embedded filename %q", entry.Name())
		}
		if _, duplicate := want[version]; duplicate {
			return fmt.Errorf("migration check: duplicate embedded version %d", version)
		}
		want[version] = struct{}{}
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return fmt.Errorf("migration check: no embedded migrations for %s", engine)
	}

	// Match goose's latest-record-per-version rule, but read the table directly.
	// goose.GetDBVersionContext creates goose_db_version when it is missing,
	// which would violate a worker's read-only schema contract.
	rows, err := db.QueryContext(ctx, `SELECT version_id, is_applied FROM goose_db_version ORDER BY id DESC`)
	if err != nil {
		return fmt.Errorf("migration check: read goose_db_version (run reactor migrate before starting workers): %w", err)
	}
	defer rows.Close()
	seen := make(map[int64]bool, len(want))
	var current int64
	for rows.Next() {
		var version int64
		var applied bool
		if err := rows.Scan(&version, &applied); err != nil {
			return fmt.Errorf("migration check: scan goose_db_version: %w", err)
		}
		if _, alreadySeen := seen[version]; alreadySeen {
			continue
		}
		seen[version] = applied
		if applied && version > current {
			current = version
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migration check: read goose_db_version: %w", err)
	}
	if current != latest {
		return fmt.Errorf("migration check: database version %d does not match embedded version %d; migrate with the matching release before starting workers", current, latest)
	}
	for version := range want {
		if !seen[version] {
			return fmt.Errorf("migration check: embedded version %d is not applied; migrate with the matching release before starting workers", version)
		}
	}
	return nil
}
