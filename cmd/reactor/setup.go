package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/server"
)

// cmdSetup is the one-command first-boot wizard. Combines `reactor
// init` + `reactor migrate` + the BasicAuth credential hashing step
// + writes a reactor.env that is valid for both systemd EnvironmentFile= and
// shell use. In a shell, load it with `set -a; . <root>/reactor.env; set +a`.
//
// Idempotent on partial completion: refuses to overwrite an existing
// master.key (operator must rm + re-run if they really mean it).
// Re-running against a directory that already has master.key but no
// .env still completes the BasicAuth step.
//
//	reactor setup
//	reactor setup --root /var/lib/reactor --db sqlite:///var/lib/reactor/reactor.db
//	reactor setup --non-interactive --admin-user admin --admin-password $PW (CI path)
func cmdSetup(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	root := fs.String("root", defaultRoot(), "Reactor state directory (created if missing)")
	dbFlag := fs.String("db", "", "database URL (defaults to sqlite:// inside --root)")
	user := fs.String("admin-user", "", "BasicAuth username (prompted if empty)")
	password := fs.String("admin-password", "", "BasicAuth password (prompted if empty; never echoed unless via --admin-password)")
	nonInteractive := fs.Bool("non-interactive", false, "fail rather than prompt when a required value is missing (CI path)")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	if *root == "" {
		return errors.New("setup: --root required (and HOME unset)")
	}
	dbURL := *dbFlag
	if dbURL == "" {
		dbURL = "sqlite://" + filepath.Join(*root, "reactor.db")
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Reactor first-boot setup")
	fmt.Println(strings.Repeat("=", 40))
	fmt.Printf("State directory: %s\n", *root)
	fmt.Printf("Database URL:    %s\n", dbURL)
	fmt.Println()

	// Step 1: state dir + master key.
	if err := os.MkdirAll(*root, 0o700); err != nil {
		return fmt.Errorf("setup: mkdir %s: %w", *root, err)
	}
	if err := os.MkdirAll(filepath.Join(*root, "workflows"), 0o700); err != nil {
		return fmt.Errorf("setup: mkdir workflows: %w", err)
	}
	keyPath := filepath.Join(*root, "master.key")
	if _, err := os.Stat(keyPath); err == nil {
		fmt.Printf("[1/3] Master key already exists at %s, keeping.\n", keyPath)
	} else {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("setup: rand: %w", err)
		}
		hexed := hex.EncodeToString(buf)
		if err := os.WriteFile(keyPath, []byte(hexed+"\n"), 0o600); err != nil {
			return fmt.Errorf("setup: write master.key: %w", err)
		}
		fmt.Printf("[1/3] Master key written to %s (mode 0600).\n", keyPath)
		fmt.Println("      Back this file up. Without it, no credential in the vault can be decrypted.")
	}

	// Step 2: migrations.
	fmt.Printf("[2/3] Running migrations against %s ...\n", dbURL)
	if err := migrate.Up(ctx, log, dbURL); err != nil {
		return fmt.Errorf("setup: migrate: %w", err)
	}
	fmt.Println("      Schema up to date.")

	// Step 3: admin credentials.
	finalUser := strings.TrimSpace(*user)
	if finalUser == "" {
		if *nonInteractive {
			return errors.New("setup: --admin-user required in --non-interactive mode")
		}
		fmt.Print("[3/3] Admin username (default 'admin'): ")
		line, _ := reader.ReadString('\n')
		finalUser = strings.TrimSpace(line)
		if finalUser == "" {
			finalUser = "admin"
		}
	}
	finalPassword := *password
	if finalPassword == "" {
		if *nonInteractive {
			return errors.New("setup: --admin-password required in --non-interactive mode")
		}
		pw, err := readPasswordTwice("Admin password: ", "Confirm password: ")
		if err != nil {
			return err
		}
		finalPassword = pw
	}
	if len(finalPassword) < 8 {
		return errors.New("setup: admin password must be at least 8 characters")
	}

	// Mint an argon2id PHC string for the dashboard's BasicAuth verifier.
	// SHA-256 hex still works (newPasswordVerifier sniffs the prefix), but
	// new setups should ship the GPU-resistant format by default. The
	// salt is 16 random bytes per OWASP recommendation.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("setup: salt: %w", err)
	}
	hash := server.EncodeArgon2idPHC(finalPassword, salt, 64*1024, 3, 2)

	envPath := filepath.Join(*root, "reactor.env")
	// Single-quote every value so the PHC string (which starts with
	// $argon2id$v=19$... and contains dollar signs in argon2 segments)
	// is not shell-expanded when an operator sources the file. Double
	// quotes would have $argon2id$ collapse to nothing on `source` and
	// the dashboard would refuse every login.
	envBody := reactorEnvBody(dbURL, finalUser, hash, *root)
	if err := os.WriteFile(envPath, []byte(envBody), 0o600); err != nil {
		return fmt.Errorf("setup: write %s: %w", envPath, err)
	}
	fmt.Printf("      Admin user '%s' configured. Password hash written to %s (mode 0600).\n", finalUser, envPath)

	// Seed the first admin into the users table so the dashboard's
	// session middleware has a real account on first boot. Idempotent:
	// re-running setup against an existing root upserts the password
	// rather than creating a duplicate.
	if err := seedFirstAdmin(ctx, dbURL, finalUser, finalPassword); err != nil {
		// Surface but do not fail: legacy env-var BasicAuth still works.
		fmt.Printf("      WARN: seeding users table failed (env-var BasicAuth will still work): %v\n", err)
	} else {
		fmt.Printf("      Admin user '%s' seeded into the users table.\n", finalUser)
	}

	fmt.Println()
	fmt.Println("Setup complete. Start the daemon with:")
	fmt.Printf("  set -a; . %s; set +a; reactor serve --root %s\n", envPath, *root)
	fmt.Println()
	fmt.Println("Then open http://127.0.0.1:7777/ in a browser.")
	return nil
}

// reactorEnvBody returns the shared operator environment file. Keep this in
// systemd's EnvironmentFile= assignment format (KEY=value, without `export`)
// so the setup-produced file can be loaded directly by the packaged unit.
// `set -a` makes the same assignments available to a child process when the
// file is sourced from an interactive shell.
func reactorEnvBody(dbURL, user, hash, root string) string {
	return fmt.Sprintf(`# Reactor environment, generated by `+"`reactor setup`"+`.
# Shell: set -a; . this-file; set +a; reactor serve
# systemd: use this file with EnvironmentFile=.
REACTOR_DB_URL=%s
REACTOR_BASIC_AUTH_USER=%s
REACTOR_BASIC_AUTH_PASSWORD_SHA256=%s
REACTOR_ROOT=%s
`, shellSingleQuote(dbURL), shellSingleQuote(user), shellSingleQuote(hash), shellSingleQuote(root))
}

// readPasswordTwice prompts twice + verifies they match. Disables tty
// echo via golang.org/x/term so the password never appears on screen.
// Falls back to plain stdin read when stdin isn't a tty (CI path with
// echo'd input, intentionally allowed when --non-interactive=false but
// a pipe is feeding the values).
func readPasswordTwice(p1, p2 string) (string, error) {
	read := func(prompt string) (string, error) {
		fmt.Print(prompt)
		if term.IsTerminal(int(os.Stdin.Fd())) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		}
		// Stdin is a pipe; read a line + trim.
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	a, err := read(p1)
	if err != nil {
		return "", err
	}
	b, err := read(p2)
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("setup: passwords did not match")
	}
	return a, nil
}

// shellSingleQuote returns s wrapped in single quotes, with embedded
// single quotes escaped via the standard sh idiom '\”. Used by the
// reactor.env writer so values containing $ (argon2id PHC strings,
// connection-string passwords with $) survive a `source <file>` step
// without shell variable expansion.
func shellSingleQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// seedFirstAdmin inserts (or upserts the password of) the named user
// into the users table with role=admin. Used by the setup wizard so
// the dashboard's session login works out of the box. Idempotent on
// re-runs: if the user already exists, the password is re-hashed and
// stored without disturbing role / disabled / created_at.
func seedFirstAdmin(ctx context.Context, dbURL, username, password string) error {
	db, engine, err := migrate.Open(dbURL)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()
	authEngine := auth.EngineSQLite
	if engine == migrate.EnginePostgres {
		authEngine = auth.EnginePostgres
	}
	store := auth.New(db, authEngine)
	if existing, err := store.GetUserByUsername(ctx, username); err == nil {
		// User exists: update the password + force role=admin so a
		// re-run of setup recovers a lost admin password.
		phc, herr := auth.HashPassword(password)
		if herr != nil {
			return herr
		}
		bindQ := `UPDATE users SET password_phc = $1, role = 'admin', disabled = 0, updated_at = $2 WHERE id = $3`
		if engine == migrate.EnginePostgres {
			bindQ = `UPDATE users SET password_phc = $1, role = 'admin', disabled = false, updated_at = $2 WHERE id = $3`
		}
		if engine != migrate.EnginePostgres {
			bindQ = strings.ReplaceAll(bindQ, "$1", "?")
			bindQ = strings.ReplaceAll(bindQ, "$2", "?")
			bindQ = strings.ReplaceAll(bindQ, "$3", "?")
		}
		if _, err := db.ExecContext(ctx, bindQ, phc, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), existing.ID); err != nil {
			return fmt.Errorf("update existing admin: %w", err)
		}
		return nil
	}
	if _, err := store.CreateUser(ctx, username, password, auth.RoleAdmin); err != nil {
		return fmt.Errorf("create admin: %w", err)
	}
	return nil
}
