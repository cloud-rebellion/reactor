package migrate

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	dbpkg "github.com/bright-interaction/reactor/internal/db"
)

var migrationFilename = regexp.MustCompile("^([0-9]{4})_.+\\.sql$")

// TestEmbeddedMigrationsStayMirrored prevents a schema change from silently
// shipping for one supported database engine only. Dialect-specific SQL is
// expected; the migration version and direction contract is not.
func TestEmbeddedMigrationsStayMirrored(t *testing.T) {
	t.Parallel()

	sqlite := embeddedMigrationSet(t, "sqlite")
	postgres := embeddedMigrationSet(t, "postgres")

	if got, want := strings.Join(sqlite, "\n"), strings.Join(postgres, "\n"); got != want {
		t.Fatalf("migration filenames differ between sqlite and postgres:\nsqlite:\n%s\npostgres:\n%s", got, want)
	}

	for _, name := range sqlite {
		for _, engine := range []string{"sqlite", "postgres"} {
			raw, err := fs.ReadFile(dbpkg.Migrations, filepath.Join("migrations", engine, name))
			if err != nil {
				t.Fatalf("read %s %s: %v", engine, name, err)
			}
			sql := string(raw)
			if !strings.Contains(sql, "-- +goose Up") {
				t.Errorf("%s %s is missing goose Up marker", engine, name)
			}
			if !strings.Contains(sql, "-- +goose Down") {
				t.Errorf("%s %s is missing goose Down marker", engine, name)
			}
		}
	}
}

func embeddedMigrationSet(t *testing.T, engine string) []string {
	t.Helper()
	entries, err := fs.ReadDir(dbpkg.Migrations, filepath.Join("migrations", engine))
	if err != nil {
		t.Fatalf("read %s migration directory: %v", engine, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		if !migrationFilename.MatchString(entry.Name()) {
			t.Fatalf("%s contains malformed migration filename %q", engine, entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatalf("%s contains no migrations", engine)
	}
	return names
}
