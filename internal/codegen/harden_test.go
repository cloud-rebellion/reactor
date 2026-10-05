package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLintRejectsSDKTestBindingsInWorkflowSource(t *testing.T) {
	for _, tc := range []struct {
		name, source, want string
	}{
		{"mail binding reference", `package main
import "github.com/bright-interaction/reactor/sdk/email"
var _ = email.BindMailSender`, "test-binding hook"},
		{"aliased connector binding", `package main
import connector "github.com/bright-interaction/reactor/sdk/http"
func f() { _ = connector.BindConnectorRequester }`, "test-binding hook"},
		{"vault binding", `package main
import "github.com/bright-interaction/reactor/sdk/vault"
func f() { vault.BindFunc(nil) }`, "test-binding hook"},
		{"observed block override", `package main
import "github.com/bright-interaction/reactor/sdk/blocks"
func f() { _ = blocks.WithJoinObserver }`, "test-binding hook"},
		{"dot import of mail test hooks", `package main
import . "github.com/bright-interaction/reactor/sdk/email"
var _ = BindMailSender`, "test-binding hook"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issues := Lint([]byte(tc.source), "workflow.go")
			if len(issues) == 0 || !strings.Contains(issues[0].Message, tc.want) {
				t.Fatalf("lint issues = %+v, want %q", issues, tc.want)
			}
		})
	}
	clean := `package main
import "github.com/bright-interaction/reactor/sdk/email"
var _ = email.SendConnected`
	if issues := Lint([]byte(clean), "workflow.go"); len(issues) != 0 {
		t.Fatalf("connected-mail authoring was rejected: %+v", issues)
	}
	dotClean := `package main
import . "github.com/bright-interaction/reactor/sdk/email"
var _ = SendConnected`
	if issues := Lint([]byte(dotClean), "workflow.go"); len(issues) != 0 {
		t.Fatalf("ordinary dot-imported email call was rejected: %+v", issues)
	}
}

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
	for _, imp := range []string{
		"C", "unsafe", "plugin", "os", "os/exec", "syscall", "os/signal",
		"net", "net/http", "net/smtp", "net/rpc", "net/rpc/jsonrpc", "crypto/tls",
		"io/ioutil", "go/parser", "text/template", "html/template",
		"debug/elf", "debug/macho", "debug/pe", "debug/plan9obj", "log/syslog",
	} {
		dir := t.TempDir()
		writeGo(t, dir, "main.go", "package main\nimport _ \""+imp+"\"\nfunc main() {}\n")
		if err := CheckAllowedImports(dir); err == nil {
			t.Errorf("import %q should be rejected by the allowlist denylist", imp)
		}
	}
}

// TestCheckAllowedImportsRejectsDangerousStdlibSubpackages guards the
// segment-aware prefix fence. Checking only exact package names would let a
// workflow import net/http/httptest or os/user even though those packages
// pull in the raw network/filesystem surfaces the authoring boundary forbids.
func TestCheckAllowedImportsRejectsDangerousStdlibSubpackages(t *testing.T) {
	t.Parallel()
	for _, imp := range []string{"net/http/httptest", "net/http/httputil", "net/rpc/jsonrpc", "os/user", "syscall/js", "crypto/tls"} {
		imp := imp
		t.Run(imp, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeGo(t, dir, "main.go", "package main\nimport _ \""+imp+"\"\nfunc main() {}\n")
			if err := CheckAllowedImports(dir); err == nil {
				t.Fatalf("import %q should be rejected by the denied package-prefix fence", imp)
			}
		})
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
	"net/url"
	"github.com/bright-interaction/reactor/sdk"
)
func main() { _ = context.Background(); _, _ = url.Parse("https://example.com"); fmt.Println(sdk.Version) }
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
