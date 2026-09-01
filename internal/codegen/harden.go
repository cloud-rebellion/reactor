package codegen

import (
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// StageWorkflowSource copies a workflow into a private temporary directory for
// compilation. Caller-owned module files are deliberately omitted because
// Reactor creates a trusted module graph in the staging directory; the source
// tree itself is never rewritten by a build. Symlinks and special files are
// rejected so staging cannot read outside the selected workflow directory or
// block on a device/FIFO.
func StageWorkflowSource(src string) (string, func(), error) {
	info, err := os.Stat(src)
	if err != nil {
		return "", nil, fmt.Errorf("stage workflow source: stat: %w", err)
	}
	if !info.IsDir() {
		return "", nil, fmt.Errorf("stage workflow source: %q is not a directory", src)
	}
	for _, banned := range []string{"vendor", "go.work", "go.work.sum"} {
		if _, err := os.Lstat(filepath.Join(src, banned)); err == nil {
			return "", nil, fmt.Errorf("stage workflow source: %q is not allowed in a workflow source tree", banned)
		} else if !os.IsNotExist(err) {
			return "", nil, fmt.Errorf("stage workflow source: inspect %q: %w", banned, err)
		}
	}

	stage, err := os.MkdirTemp("", "reactor-workflow-build-")
	if err != nil {
		return "", nil, fmt.Errorf("stage workflow source: create temporary directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(stage) }
	fail := func(err error) (string, func(), error) {
		cleanup()
		return "", nil, err
	}

	err = filepath.WalkDir(src, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("stage workflow source: symlink %q is not allowed", rel)
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.Mkdir(filepath.Join(stage, rel), 0o700)
		}
		if rel == "go.mod" || rel == "go.sum" {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("stage workflow source: special file %q is not allowed", rel)
		}

		input, err := os.Open(path)
		if err != nil {
			return err
		}
		openedInfo, err := input.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() {
			_ = input.Close()
			if err != nil {
				return err
			}
			return fmt.Errorf("stage workflow source: file %q changed while staging", rel)
		}
		output, err := os.OpenFile(filepath.Join(stage, rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = input.Close()
			return err
		}
		if _, err := io.Copy(output, input); err != nil {
			_ = input.Close()
			_ = output.Close()
			return err
		}
		if err := input.Close(); err != nil {
			_ = output.Close()
			return err
		}
		return output.Close()
	})
	if err != nil {
		return fail(fmt.Errorf("stage workflow source: %w", err))
	}
	return stage, cleanup, nil
}

// AllowedImportPrefixes is the set of non-stdlib import path prefixes a
// generated or uploaded workflow may use. Everything in the standard
// library (import paths whose first segment contains no dot) is allowed
// implicitly; everything else must match one of these prefixes. This is
// the gate that stops a hostile brief or saved edit from pulling an
// arbitrary third-party module that could run attacker-controlled code
// (cgo directives, linker flags) at `go build` time.
var AllowedImportPrefixes = []string{
	"github.com/bright-interaction/reactor",
}

// deniedImports are import paths that PARSE as standard library (no dot in the
// first segment) but are forbidden regardless: they are the build-time-exec and
// sandbox-escape vectors the allowlist exists to stop. "C" is the cgo
// pseudo-import (a `#cgo`/`#include` preamble runs an arbitrary C compiler at
// build time); the rest give a workflow OS/process/memory reach it must never
// have. Checked in EVERY scanned file, not just main.go, so a subdir file
// cannot smuggle them past the lint pass.
//
// NB this list is NOT containment, and denying os/exec does not by itself deny
// process spawning: plain "os" is allowlisted as stdlib and os.StartProcess
// spawns a process just as well, so `reactor lint` bans that call separately.
// Assembly (.s) files are not scanned either, since this walk parses only .go.
// See docs/security.md Layer 4: the real boundary is the OS user the daemon
// runs as.
var deniedImports = map[string]struct{}{
	"C":         {},
	"unsafe":    {},
	"plugin":    {},
	"os/exec":   {},
	"syscall":   {},
	"os/signal": {},
}

// CheckAllowedImports parses every .go file under dir (RECURSIVELY, including
// subdirectories) and returns an error if any import path is neither standard
// library nor under an allowed prefix, or is on the denylist. Workflows are
// sandboxed at runtime but `go build` is not, so this static check runs BEFORE
// any compilation. The recursion matters: an uploaded tarball can carry source
// in subdirectories that `go build .` would still compile.
func CheckAllowedImports(dir string) error {
	var disallowed []string
	seen := map[string]struct{}{}
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip vendored/VCS trees; they never belong in a workflow module.
			if name := d.Name(); name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		// Skip files the Go build itself ignores: anything starting with "." or
		// "_" is never compiled, so scanning it can only produce false failures.
		// The one that actually bites is macOS AppleDouble metadata: a plain
		// `tar czf` on a Mac emits a `._main.go` sidecar next to every file, and
		// parsing that binary blob failed the whole upload with
		// "illegal character NUL", which every Mac user hit and which surfaced
		// only as an opaque 500. Skipping matches the compiler's own rule, so
		// nothing an attacker hides here would ever be built either.
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return fmt.Errorf("import allowlist: parse %s: %w", path, perr)
		}
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if importAllowed(p) {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			disallowed = append(disallowed, p)
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("import allowlist: %w", walkErr)
	}
	if len(disallowed) > 0 {
		sort.Strings(disallowed)
		return fmt.Errorf("import allowlist: workflow imports disallowed package(s): %s (only the standard library and %s are permitted)",
			strings.Join(disallowed, ", "), strings.Join(AllowedImportPrefixes, ", "))
	}
	return nil
}

// importAllowed reports whether a single import path is permitted: stdlib
// (no dot in the first path segment) or under an allowed prefix, and NOT on
// the denylist.
func importAllowed(path string) bool {
	if _, denied := deniedImports[path]; denied {
		return false
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	if !strings.Contains(first, ".") {
		return true // standard library
	}
	for _, prefix := range AllowedImportPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// SecureBuildEnv returns the environment for an untrusted `go build`. It
// strips every REACTOR_* secret and the Anthropic key from the inherited
// environment (the build subprocess has no business reading the vault key
// or DB URL), then forces a hermetic, cgo-free toolchain:
//
//   - CGO_ENABLED=0 disables cgo, removing the #cgo directive vector that
//     lets a module invoke an arbitrary C compiler/linker at build time.
//   - GOTOOLCHAIN=local pins the toolchain so a hostile go.mod `toolchain`
//     line can't trigger a network toolchain download + exec.
//   - GOFLAGS=-mod=mod keeps module resolution working for the SDK import.
//   - GOWORK=off prevents a workspace file above the source directory from
//     replacing Reactor's freshly generated module graph.
//
// buildEnvAllowlist is the set of environment variables the untrusted
// `go build` of workflow source may inherit. It is an ALLOWLIST, not a
// denylist. A denylist (strip REACTOR_/ARACHNE_/ANTHROPIC_) leaks every OTHER
// secret in the daemon's process env (CLOUDFLARE_TOKEN, AWS_SECRET_ACCESS_KEY,
// PGPASSWORD, GITHUB_TOKEN, ...) into a build that can execute attacker code at
// build time. Only toolchain-relevant, non-secret vars pass; the hermetic pins
// are appended explicitly below so an inherited GOFLAGS/GOPROXY/CGO_ENABLED
// cannot override them (last value wins in Go's env dedup).
var buildEnvAllowlist = map[string]struct{}{
	"PATH": {}, "HOME": {}, "TMPDIR": {}, "TMP": {}, "TEMP": {},
	"GOROOT": {}, "GOPATH": {}, "GOCACHE": {}, "GOMODCACHE": {}, "GOTMPDIR": {},
	"GOOS": {}, "GOARCH": {}, "GOARM": {}, "GOAMD64": {}, "GO386": {}, "GOMIPS": {},
	"SSL_CERT_FILE": {}, "SSL_CERT_DIR": {},
}

func SecureBuildEnv() []string {
	env := make([]string, 0, 32)
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		if _, ok := buildEnvAllowlist[kv[:eq]]; ok {
			env = append(env, kv)
		}
	}
	// Hermetic, non-overridable pins (appended last so they beat any inherited
	// value): no cgo (kills the #cgo C-compiler exec vector), no network module
	// fetch, pinned toolchain, no on-disk go env file consulted, and -mod=mod
	// so the workflow-local SDK replace resolves from the warmed module cache.
	env = append(env,
		"CGO_ENABLED=0",
		"GOTOOLCHAIN=local",
		"GOFLAGS=-mod=mod",
		"GOWORK=off",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOENV=off",
	)
	return env
}

// BuildVCSFlag disables Go's VCS stamping on every workflow compile.
//
// `go build` stamps VCS info by default, which makes it shell out to git
// whenever the source sits inside a repository. Reactor's README tells
// operators to `git init` their state directory and the Dockerfile ships git,
// while the daemon normally runs as a different uid than whoever created that
// repo (the systemd `reactor` user, uid 65532 in the image). git then reports
// "detected dubious ownership", exits 128, and the compile fails with an
// opaque "error obtaining VCS status: exit status 128" that reaches the
// operator only as "go build: exit status 1".
//
// Nothing in Reactor reads the stamp, so this is free. Guarded by
// TestEveryGoBuildDisablesVCSStamping so a new call site cannot omit it.
const BuildVCSFlag = "-buildvcs=false"
