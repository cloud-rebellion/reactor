package commandrunner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewDockerSandboxRequiresPinnedImageAndBoundedProfile(t *testing.T) {
	base := DockerConfig{Binary: "/usr/bin/docker", Image: "registry.example/reactor@sha256:" + strings.Repeat("a", 64), MemoryBytes: 64 << 20, CPUs: "1.0", PIDsLimit: 64, TmpfsBytes: 16 << 20, MaxOutputBytes: 64 << 10}
	if sb, err := NewDockerSandbox(base); err != nil || sb == nil || !sb.Profile().Valid() {
		t.Fatalf("valid docker config: sandbox=%v err=%v profile=%+v", sb, err, func() SandboxProfile {
			if sb == nil {
				return SandboxProfile{}
			}
			return sb.Profile()
		}())
	}
	for name, mutate := range map[string]func(*DockerConfig){
		"tag":              func(c *DockerConfig) { c.Image = "registry.example/reactor:latest" },
		"relative binary":  func(c *DockerConfig) { c.Binary = "docker" },
		"unbounded output": func(c *DockerConfig) { c.MaxOutputBytes = (1 << 20) + 1 },
		"invalid cpu":      func(c *DockerConfig) { c.CPUs = "1;id" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := NewDockerSandbox(cfg); err == nil {
				t.Fatalf("invalid docker config accepted: %+v", cfg)
			}
		})
	}
}

func TestDockerSandboxRejectsUnsafeWorkingDirectoryAndCredentials(t *testing.T) {
	sb, err := NewDockerSandbox(DockerConfig{Binary: "/usr/bin/docker", Image: "registry.example/reactor@sha256:" + strings.Repeat("b", 64), MemoryBytes: 64 << 20, CPUs: "1", PIDsLimit: 64, TmpfsBytes: 16 << 20, MaxOutputBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]SandboxRequest{
		"path traversal": {Command: "true", WorkingDir: "/workspace/../host"},
		"host root":      {Command: "true", WorkingDir: "/"},
		"credential":     {Command: "true", CredentialIDs: []string{"cred_1"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sb.Execute(context.Background(), req)
			if err == nil {
				t.Fatal("unsafe request unexpectedly accepted")
			}
			if name == "credential" && !errors.Is(err, ErrCredentialBoundary) {
				t.Fatalf("credential error=%v", err)
			}
		})
	}
	if !safeContainerWorkdir("/workspace/jobs/../checks") {
		t.Fatal("canonicalizable workspace path rejected")
	}
	if safeContainerWorkdir("/workspace/../../host") || safeContainerWorkdir("relative") {
		t.Fatal("unsafe workspace path accepted")
	}
}

func TestDockerSandboxCredentialPipeAtCLI(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The wrapper supplies the test selector; it contains no credential data.
	fakeDocker := filepath.Join(t.TempDir(), "docker")
	quotedBinary := "'" + strings.ReplaceAll(binary, "'", "'\\''") + "'"
	script := "#!/bin/sh\nexec " + quotedBinary + " -test.run=^TestDockerCLIHelperProcess$ -- \"$@\"\n"
	if err := os.WriteFile(fakeDocker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	sb, err := NewDockerSandbox(DockerConfig{Binary: fakeDocker, Image: "registry.example/reactor@sha256:" + strings.Repeat("c", 64), MemoryBytes: 64 << 20, CPUs: "1", PIDsLimit: 64, TmpfsBytes: 16 << 20, MaxOutputBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("token=value#with whitespace")
	second := []byte("backup-token")
	ids := []string{"cred_api", "cred_backup"}
	bindings := []CredentialBinding{
		{CredentialID: ids[0], Environment: CredentialEnvironmentName(ids[0]), Value: first},
		{CredentialID: ids[1], Environment: CredentialEnvironmentName(ids[1]), Value: second},
	}
	result, err := sb.ExecuteWithCredentials(context.Background(), SandboxRequest{Command: "true", CredentialIDs: ids}, CredentialMaterialization{Bindings: bindings})
	if err != nil || result.ExitCode != 0 || string(result.Stdout) != "docker-cli-accepted\n" || len(result.Stderr) != 0 {
		t.Fatalf("fake Docker CLI rejected credential pipe: exit=%d launch_error=%t stdout_bytes=%d stderr_bytes=%d", result.ExitCode, err != nil, len(result.Stdout), len(result.Stderr))
	}
	if !bytes.Equal(first, make([]byte, len(first))) || !bytes.Equal(second, make([]byte, len(second))) {
		t.Fatal("materialized credential bytes were not cleared")
	}
	for name, value := range map[string][]byte{
		"newline":       []byte("line1\nline2"),
		"invalid UTF-8": {0xff},
		"scanner limit": bytes.Repeat([]byte("x"), bufio.MaxScanTokenSize),
	} {
		if err := validateCredentialBindings(ids[:1], []CredentialBinding{{CredentialID: ids[0], Environment: CredentialEnvironmentName(ids[0]), Value: value}}); !errors.Is(err, ErrCredentialBoundary) {
			t.Fatalf("%s credential validation = %v, want ErrCredentialBoundary", name, err)
		}
	}
}

// The subprocess opens --env-file itself, as Docker's CLI parser does. It
// checks the transport while credentials still exist, before cleanup runs.
func TestDockerCLIHelperProcess(t *testing.T) {
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return
	}
	fail := func(reason string) {
		_, _ = fmt.Fprintln(os.Stderr, reason)
		os.Exit(17)
	}
	args := os.Args[separator+1:]
	if len(args) == 0 || args[0] != "run" {
		fail("missing Docker run command")
	}
	for _, text := range append(append([]string(nil), args...), os.Environ()...) {
		if strings.Contains(text, "token=value#with whitespace") || strings.Contains(text, "backup-token") {
			fail("credential appeared in child arguments or environment")
		}
	}
	var envPath, cidPath string
	for i, arg := range args {
		if (arg == "--env-file" || arg == "--cidfile") && i+1 >= len(args) {
			fail("Docker option has no path")
		}
		switch arg {
		case "--env-file":
			if envPath != "" {
				fail("multiple env-file options")
			}
			envPath = args[i+1]
		case "--cidfile":
			cidPath = args[i+1]
		}
	}
	if envPath != "/dev/stdin" || cidPath == "" {
		fail("credential pipe or container ID path missing")
	}
	entries, err := os.ReadDir(filepath.Dir(cidPath))
	if err != nil || len(entries) != 0 {
		fail("host temp directory contains a file before Docker starts")
	}
	file, err := os.Open(envPath)
	if err != nil {
		fail("cannot open Docker env-file pipe")
	}
	raw, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil {
		fail("cannot read Docker env-file pipe")
	}
	want := CredentialEnvironmentName("cred_api") + "=token=value#with whitespace\n" + CredentialEnvironmentName("cred_backup") + "=backup-token\n"
	if string(raw) != want {
		fail("Docker env-file contents differ")
	}
	_, _ = fmt.Fprintln(os.Stdout, "docker-cli-accepted")
	os.Exit(0)
}

func TestBoundedCaptureRetainsOnlyConfiguredBytes(t *testing.T) {
	var c boundedCapture
	c.limit = 4
	if n, err := c.Write([]byte("abcdef")); err != nil || n != 6 || string(c.Bytes()) != "abcd" || !c.truncated {
		t.Fatalf("capture n=%d err=%v bytes=%q truncated=%v", n, err, c.Bytes(), c.truncated)
	}
}
