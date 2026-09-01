package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGo(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCheckAllowedImportsRejectsDangerousStdlib guards the denylist: cgo's "C"
// pseudo-import and the process/memory-reach stdlib packages must be refused
// even though they parse as "standard library" (no dot in the first segment).
func TestCheckAllowedImportsRejectsDangerousStdlib(t *testing.T) {
	for _, imp := range []string{"C", "unsafe", "plugin", "os/exec", "syscall", "os/signal"} {
		dir := t.TempDir()
		writeGo(t, dir, "main.go", "package main\nimport _ \""+imp+"\"\nfunc main() {}\n")
		if err := CheckAllowedImports(dir); err == nil {
			t.Errorf("import %q should be rejected by the allowlist denylist", imp)
		}
	}
}

// TestCheckAllowedImportsScansSubdirs guards the recursive walk: an uploaded
// tarball can hide a dangerous import in a subdirectory that `go build .`
// would still compile, so the scan must descend, not just read the top level.
func TestCheckAllowedImportsScansSubdirs(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "main.go", "package main\nfunc main() {}\n")
	sub := filepath.Join(dir, "evil")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeGo(t, sub, "evil.go", "package evil\nimport _ \"os/exec\"\n")
	if err := CheckAllowedImports(dir); err == nil {
		t.Error("dangerous import in a subdirectory should be rejected")
	}
}

// TestSecureBuildEnvAllowlistDropsNonPrefixedSecret guards the allowlist form
// of SecureBuildEnv: a secret in an arbitrarily-named env var (not REACTOR_/
// ARACHNE_-prefixed) must NOT reach the untrusted go-build subprocess.
func TestSecureBuildEnvAllowlistDropsNonPrefixedSecret(t *testing.T) {
	t.Setenv("CLOUDFLARE_TOKEN", "cf-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("PGPASSWORD", "pg-secret")
	t.Setenv("PATH", "/usr/bin")
	joined := strings.Join(SecureBuildEnv(), "\n")
	for _, leaked := range []string{"cf-secret", "aws-secret", "pg-secret", "CLOUDFLARE_TOKEN", "PGPASSWORD"} {
		if strings.Contains(joined, leaked) {
			t.Errorf("build env leaked non-prefixed secret %q (denylist->allowlist regression)", leaked)
		}
	}
	for _, want := range []string{"CGO_ENABLED=0", "GOWORK=off", "GOPROXY=off", "GOENV=off", "PATH=/usr/bin"} {
		if !strings.Contains(joined, want) {
			t.Errorf("build env missing hermetic pin %q", want)
		}
	}
}

// TestCheckAllowedImportsRejectsThirdParty is the regression test for the
// build-time RCE ship-blocker: a workflow that imports an arbitrary
// third-party module must be refused before `go build` runs.
func TestCheckAllowedImportsRejectsThirdParty(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "main.go", `package main
import (
	"fmt"
	"github.com/evil/pwn"
)
func main() { fmt.Println(pwn.Run()) }
`)
	err := CheckAllowedImports(dir)
	if err == nil {
		t.Fatal("expected disallowed-import error, got nil")
	}
	if !strings.Contains(err.Error(), "github.com/evil/pwn") {
		t.Fatalf("error should name the offending import, got: %v", err)
	}
}

// TestCheckAllowedImportsAllowsStdlibAndSDK confirms the gate doesn't
// reject the legitimate surface: standard library + the Reactor SDK.
func TestCheckAllowedImportsAllowsStdlibAndSDK(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "main.go", `package main
import (
	"context"
	"fmt"
	"github.com/bright-interaction/reactor/sdk"
)
func main() { _ = context.Background(); fmt.Println(sdk.Version) }
`)
	if err := CheckAllowedImports(dir); err != nil {
		t.Fatalf("stdlib + SDK imports should pass, got: %v", err)
	}
}

func TestStageWorkflowSourceIsNonDestructiveAndRejectsSymlinks(t *testing.T) {
	t.Run("preserves caller module files", func(t *testing.T) {
		source := t.TempDir()
		writeGo(t, source, "main.go", "package main\nfunc main() {}\n")
		module := []byte("module caller-owned\n")
		if err := os.WriteFile(filepath.Join(source, "go.mod"), module, 0o600); err != nil {
			t.Fatal(err)
		}

		stage, cleanup, err := StageWorkflowSource(source)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if _, err := os.Stat(filepath.Join(stage, "main.go")); err != nil {
			t.Fatalf("staged main.go: %v", err)
		}
		if _, err := os.Stat(filepath.Join(stage, "go.mod")); !os.IsNotExist(err) {
			t.Fatalf("caller module file entered build stage: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(source, "go.mod"))
		if err != nil || string(got) != string(module) {
			t.Fatalf("source go.mod changed: got %q err=%v", got, err)
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		source := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside.go")
		writeGo(t, filepath.Dir(outside), filepath.Base(outside), "package main\n")
		if err := os.Symlink(outside, filepath.Join(source, "main.go")); err != nil {
			t.Fatal(err)
		}
		if _, cleanup, err := StageWorkflowSource(source); err == nil {
			cleanup()
			t.Fatal("symlink unexpectedly entered build stage")
		}
	})
}

// TestSecureBuildEnvStripsSecrets confirms the untrusted `go build`
// environment never carries the vault key, DB URL, or model key, and that
// it forces a cgo-free hermetic toolchain.
func TestSecureBuildEnvStripsSecrets(t *testing.T) {
	t.Setenv("REACTOR_MASTER_KEY", "secret")
	t.Setenv("REACTOR_DB_URL", "postgres://x")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant")
	t.Setenv("ARACHNE_MASTER_KEY", "legacy-secret")
	t.Setenv("PATH", "/usr/bin")

	env := SecureBuildEnv()
	joined := strings.Join(env, "\n")
	for _, leaked := range []string{"REACTOR_MASTER_KEY", "REACTOR_DB_URL", "ANTHROPIC_API_KEY", "ARACHNE_MASTER_KEY"} {
		if strings.Contains(joined, leaked) {
			t.Errorf("build env leaked %q", leaked)
		}
	}
	for _, want := range []string{"CGO_ENABLED=0", "GOTOOLCHAIN=local", "PATH=/usr/bin"} {
		if !strings.Contains(joined, want) {
			t.Errorf("build env missing %q", want)
		}
	}
}
