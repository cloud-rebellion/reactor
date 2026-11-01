package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Keep package input selection in the ordinary main/PR test suite. The release
// workflow runs only for tags, so a literal environment expression or an ignored
// architecture must be refused before the next release is cut. Real deb/rpm
// archive and executable verification remains a separate packaging check.
func TestNFPMPackageConfigSelectsTheRequestedBinaryAndArchitecture(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate package configuration")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../packaging/nfpm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Architecture string `yaml:"arch"`
		Contents     []struct {
			Source      string `yaml:"src"`
			Destination string `yaml:"dst"`
			Expand      bool   `yaml:"expand"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatalf("parse actual nFPM configuration: %v", err)
	}
	binaryIndex := -1
	for i, content := range config.Contents {
		if content.Destination != "/usr/bin/reactor" {
			continue
		}
		if binaryIndex != -1 {
			t.Fatal("multiple package inputs replace /usr/bin/reactor")
		}
		binaryIndex = i
	}
	if binaryIndex == -1 {
		t.Fatal("package configuration omits its installed binary")
	}
	binary := config.Contents[binaryIndex]
	if !binary.Expand {
		t.Error("binary content must enable nFPM environment expansion")
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			requestedBinary := "dist/reactor-release-linux-" + architecture
			t.Setenv("REACTOR_ARCH", architecture)
			t.Setenv("REACTOR_BINARY", requestedBinary)
			// nFPM v2 expands with os.Expand and os.Getenv. Shell-style :-
			// defaults are not supported; missing names become empty strings.
			if got := os.ExpandEnv(config.Architecture); got != architecture {
				t.Fatalf("package architecture = %q, requested %q", got, architecture)
			}
			if got := os.ExpandEnv(binary.Source); got != requestedBinary {
				t.Fatalf("package binary = %q, requested %q", got, requestedBinary)
			}
		})
	}
}

// TestNFPMPackageWorkflowConsumesItsUploadedTaggedBinaries replays the actual
// release YAML's producer and consumer shell blocks. Only go/sha256sum/nfpm are
// fixture tools: this checks the workflow handover, not real package archives.
func TestNFPMPackageWorkflowConsumesItsUploadedTaggedBinaries(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate release workflow")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	raw, err := os.ReadFile(filepath.Join(root, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	type step struct {
		Name string
		Uses string
		Run  string
		With map[string]any
		Env  map[string]string
	}
	var workflow struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct{ Include []map[string]string }
			}
			Steps []step
		}
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse actual release workflow: %v", err)
	}
	var buildScript, packageScript, uploadPath, downloadPath string
	var mergeMultiple bool
	var buildEnv, packageEnv map[string]string
	for _, s := range workflow.Jobs["build"].Steps {
		if s.Name == "build" {
			buildScript = s.Run
			buildEnv = s.Env
		}
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") {
			uploadPath, _ = s.With["path"].(string)
		}
	}
	for _, s := range workflow.Jobs["package"].Steps {
		if s.Name == "build .deb + .rpm (amd64 + arm64)" {
			packageScript = s.Run
			packageEnv = s.Env
		}
		if strings.HasPrefix(s.Uses, "actions/download-artifact@") {
			downloadPath, _ = s.With["path"].(string)
			mergeMultiple, _ = s.With["merge-multiple"].(bool)
		}
	}
	if buildScript == "" || packageScript == "" || !mergeMultiple || uploadPath != "dist/" || downloadPath != "dist" {
		t.Fatal("release binary upload/download handover is missing or changed")
	}
	if buildEnv["GOOS"] != "${{ matrix.goos }}" || buildEnv["GOARCH"] != "${{ matrix.goarch }}" || packageEnv["REACTOR_VERSION"] != "${{ github.ref_name }}" {
		t.Fatal("release environment no longer maps the actual matrix and raw tag")
	}
	const tag = "v0.3.2"
	work := t.TempDir()
	packageDir := filepath.Join(work, "package")
	if err := os.MkdirAll(filepath.Join(packageDir, downloadPath), 0755); err != nil {
		t.Fatal(err)
	}
	run := func(dir, script string, env ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/bin/sh", "-e", "-c", script)
		cmd.Dir = dir
		cmd.Env = append([]string{"PATH=/usr/bin:/bin", "GITHUB_REF_NAME=" + tag}, env...)
		cmd.WaitDelay = time.Second
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("replay actual release step: %v\n%s", err, output)
		}
	}
	const producerTools = `
go() {
  [ "$1" = build ] || return 81
  out=''
  while [ "$#" -gt 0 ]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
  done
  [ -n "$out" ] || return 82
  printf 'owned workflow artifact\n' > "$out"
}
sha256sum() { test -f "$1" && printf 'fixture-checksum  %s\n' "$1"; }
`
	produced := make(map[string]string)
	matrix := workflow.Jobs["build"].Strategy.Matrix.Include
	if len(matrix) != 4 {
		t.Fatalf("release build matrix has %d entries, want four", len(matrix))
	}
	for _, target := range matrix {
		platform := target["goos"] + "/" + target["goarch"]
		if _, exists := produced[platform]; exists {
			t.Fatalf("duplicate release platform %s", platform)
		}
		dir := filepath.Join(work, target["goos"]+"-"+target["goarch"])
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		run(dir, producerTools+buildScript, "GOOS="+target["goos"], "GOARCH="+target["goarch"], "CGO_ENABLED=0")
		files, err := os.ReadDir(filepath.Join(dir, uploadPath))
		if err != nil || len(files) != 2 {
			t.Fatalf("actual producer must upload its binary and checksum: entries=%d err=%v", len(files), err)
		}
		for _, entry := range files {
			if !entry.Type().IsRegular() {
				t.Fatal("release producer artifact is not a regular file")
			}
			data, err := os.ReadFile(filepath.Join(dir, uploadPath, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			targetPath := filepath.Join(packageDir, downloadPath, entry.Name())
			if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
				t.Fatal("merged release artifact names collide")
			}
			if err := os.WriteFile(targetPath, data, 0644); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(entry.Name(), ".sha256") {
				produced[platform] = filepath.Join(downloadPath, entry.Name())
			}
		}
	}
	const consumerTool = `
nfpm() {
  test -f "$REACTOR_BINARY" || { printf 'missing workflow-produced binary: %s\n' "$REACTOR_BINARY" >&2; return 91; }
  printf '%s\t%s\t%s\t%s\n' "$REACTOR_ARCH" "$REACTOR_VERSION" "$REACTOR_BINARY" "$3" >> "$NFPM_CAPTURE"
}
`
	capture := filepath.Join(work, "nfpm-calls")
	run(packageDir, consumerTool+packageScript, "REACTOR_VERSION="+tag, "NFPM_CAPTURE="+capture)
	calls, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(rows) != 4 {
		t.Fatalf("package step made %d nFPM calls, want four", len(rows))
	}
	seen := make(map[string]bool)
	for _, row := range rows {
		fields := strings.Split(row, "\t")
		if len(fields) != 4 {
			t.Fatal("invalid nFPM handover receipt")
		}
		arch, version, binary, format := fields[0], fields[1], fields[2], fields[3]
		key := arch + "/" + format
		if (arch != "amd64" && arch != "arm64") || (format != "deb" && format != "rpm") || seen[key] {
			t.Fatalf("unexpected or repeated package target %s", key)
		}
		seen[key] = true
		if version != strings.TrimPrefix(tag, "v") || binary != produced["linux/"+arch] {
			t.Fatalf("nFPM handover = (%q,%q), want normalized version and actual tagged Linux artifact", version, binary)
		}
	}
}
