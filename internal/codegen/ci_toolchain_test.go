package codegen

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	dockerGoRe   = regexp.MustCompile(`FROM[^\n]*golang:([0-9]+\.[0-9]+\.[0-9]+)-alpine`)
	ciGoRe       = regexp.MustCompile(`go-version:\s*"([^"]+)"`)
	toolchainRe  = regexp.MustCompile(`(?m)^toolchain go([0-9]+\.[0-9]+\.[0-9]+)$`)
	sdkMinimumRe = regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+\.[0-9]+)$`)
)

// TestCIGoVersionMatchesDockerfile turns a two-file invariant into a test.
//
// The Dockerfile pins its golang tag deliberately: its own comment records that
// 1.26.5 was chosen to pick up the crypto/tls fix for GO-2026-5856, and warns
// that the failure mode is asymmetric --
//
//	a CI image OLDER than this stage fails loudly red, a NEWER one fails
//	silently green
//
// The repo's own GitHub Actions were pinned to 1.22 while go.mod required
// 1.25.10, so GOTOOLCHAIN=auto silently fetched 1.25.10 and every release
// binary, .deb, .rpm and Homebrew bottle shipped a stdlib OLDER than the
// container's. Green the whole time.
//
// A comment asking a human to keep two files in step is not an invariant, it is
// a countdown. This is the same lesson as the playwright image pin that drifted
// twice with a warning comment sitting right above it.
func TestCIGoVersionMatchesDockerfile(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..") // reactor/

	raw, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	matches := dockerGoRe.FindAllStringSubmatch(string(raw), -1)
	if len(matches) != 2 {
		t.Fatal("Dockerfile must contain both the daemon and workflow compiler stages")
	}
	want := matches[0][1]
	for _, pin := range []struct {
		path    string
		pattern *regexp.Regexp
	}{
		{"go.mod", toolchainRe},
		{"packaging/sdk-module.mod", sdkMinimumRe},
	} {
		body, err := os.ReadFile(filepath.Join(root, pin.path))
		if err != nil {
			t.Fatal(err)
		}
		pins := pin.pattern.FindAllStringSubmatch(string(body), -1)
		if len(pins) != 1 || pins[0][1] != want {
			t.Fatalf("%s must pin the Docker compiler %s", pin.path, want)
		}
	}
	for _, m := range matches[1:] {
		if m[1] != want {
			t.Fatalf("the Dockerfile's own stages disagree: %s vs %s (the runtime stage compiles user workflows; both must carry the patched stdlib)", want, m[1])
		}
	}

	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(workflows) == 0 {
		t.Fatal("no workflow files found; update this guard if CI moved")
	}
	for _, wf := range workflows {
		body, rerr := os.ReadFile(wf)
		if rerr != nil {
			t.Fatalf("read %s: %v", wf, rerr)
		}
		pins := ciGoRe.FindAllStringSubmatch(string(body), -1)
		if len(pins) == 0 {
			t.Fatalf("%s has no explicit Go provisioning; a sibling workflow's pin cannot cover it", filepath.Base(wf))
		}
		if strings.Contains(string(body), "go-version-file:") || strings.Contains(string(body), "GOTOOLCHAIN:") || strings.Contains(string(body), "GOTOOLCHAIN=") || strings.Contains(string(body), "container:") {
			t.Fatalf("%s introduces another Go provisioning or override path; review this guard before using it", filepath.Base(wf))
		}
		for _, m := range pins {
			if m[1] != want {
				t.Fatalf("%s pins go-version %q but the Dockerfile pins %q; release artifacts would ship a different stdlib than the image, and an OLDER CI toolchain fails silently green",
					filepath.Base(wf), m[1], want)
			}
		}
	}
}

// TestCIRunsGovulncheck keeps the vulnerability gate from quietly disappearing.
// The Dockerfile's Go pin exists BECAUSE of a CVE, so a pipeline that never
// scans is a pin nobody is checking.
func TestCIRunsGovulncheck(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "test.yml"))
	if err != nil {
		t.Fatalf("read test.yml: %v", err)
	}
	if !strings.Contains(string(body), "govulncheck") {
		t.Fatal("test.yml no longer runs govulncheck; the public CI would stop checking the toolchain and deps for known vulnerabilities")
	}
}
