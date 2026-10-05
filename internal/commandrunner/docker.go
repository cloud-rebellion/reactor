package commandrunner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/vault"
)

// DockerConfig describes the only process adapter shipped with Reactor. The
// image must be pinned by digest; tags and implicit pulls are refused. The
// binary path is operator configuration, but must be absolute so PATH cannot
// be used to replace the runtime after admission.
type DockerConfig struct {
	Binary         string
	Image          string
	MemoryBytes    int64
	CPUs           string
	PIDsLimit      int
	TmpfsBytes     int64
	MaxOutputBytes int
}

// DockerSandbox starts one disposable container per command step. It has no
// host mounts, no network, no inherited environment, no capabilities, a
// read-only root filesystem, a non-root uid, and fixed resource limits.
type DockerSandbox struct {
	binary         string
	image          string
	memoryBytes    int64
	cpus           string
	pidsLimit      int
	tmpfsBytes     int64
	maxOutputBytes int
}

var imageDigest = regexp.MustCompile(`^[^\x00-\x20]+@sha256:[0-9a-fA-F]{64}$`)
var containerID = regexp.MustCompile(`^[0-9a-fA-F]{12,64}$`)

func NewDockerSandbox(cfg DockerConfig) (*DockerSandbox, error) {
	if strings.TrimSpace(cfg.Binary) == "" || !filepath.IsAbs(cfg.Binary) || strings.IndexFunc(cfg.Binary, func(r rune) bool { return r == '\x00' || r == '\n' || r == '\r' }) >= 0 {
		return nil, errors.New("commandrunner: docker binary must be an absolute path without controls")
	}
	if !imageDigest.MatchString(cfg.Image) {
		return nil, errors.New("commandrunner: docker image must be pinned by sha256 digest")
	}
	if cfg.MemoryBytes < 16<<20 || cfg.MemoryBytes > 64<<30 {
		return nil, errors.New("commandrunner: docker memory must be between 16 MiB and 64 GiB")
	}
	if !validCPU(cfg.CPUs) {
		return nil, errors.New("commandrunner: docker cpus must be a positive decimal quota")
	}
	if cfg.PIDsLimit < 16 || cfg.PIDsLimit > 4096 {
		return nil, errors.New("commandrunner: docker pids limit must be between 16 and 4096")
	}
	if cfg.TmpfsBytes < 1<<20 || cfg.TmpfsBytes > 1<<30 {
		return nil, errors.New("commandrunner: docker tmpfs must be between 1 MiB and 1 GiB")
	}
	if cfg.MaxOutputBytes <= 0 || cfg.MaxOutputBytes > 1<<20 {
		return nil, errors.New("commandrunner: docker output limit must be between 1 byte and 1 MiB")
	}
	return &DockerSandbox{
		binary: cfg.Binary, image: cfg.Image, memoryBytes: cfg.MemoryBytes,
		cpus: cfg.CPUs, pidsLimit: cfg.PIDsLimit, tmpfsBytes: cfg.TmpfsBytes,
		maxOutputBytes: cfg.MaxOutputBytes,
	}, nil
}

func validCPU(raw string) bool {
	if strings.TrimSpace(raw) != raw || raw == "" || strings.Count(raw, ".") > 1 {
		return false
	}
	for _, r := range raw {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	value, err := strconv.ParseFloat(raw, 64)
	return err == nil && value > 0 && value <= 64
}

func (d *DockerSandbox) Profile() SandboxProfile {
	if d == nil {
		return SandboxProfile{}
	}
	return SandboxProfile{
		Name:            "docker-no-mounts-v1",
		NonRoot:         true,
		NoHostMounts:    true,
		NetworkDisabled: true,
		ReadOnlyRoot:    true,
		ResourceLimited: true,
		MaxOutputBytes:  d.maxOutputBytes,
	}
}

func (d *DockerSandbox) Execute(ctx context.Context, req SandboxRequest) (SandboxResult, error) {
	return d.execute(ctx, req, nil, nil)
}

// ExecuteStreaming is the optional live-output path. The bounded captures
// remain authoritative for the final result; the sink only adds durable
// visibility while the container is still running.
func (d *DockerSandbox) ExecuteStreaming(ctx context.Context, req SandboxRequest, sink OutputSink) (SandboxResult, error) {
	return d.execute(ctx, req, nil, sink)
}

// ExecuteWithCredentials is the explicit credential-capable Docker path. It
// sends env-file contents to the Docker CLI over stdin before the container
// starts. This adapter puts no credential values in Docker argv or a host
// file; the runner separately redacts exact values from captured output.
func (d *DockerSandbox) ExecuteWithCredentials(ctx context.Context, req SandboxRequest, materialized CredentialMaterialization) (SandboxResult, error) {
	return d.execute(ctx, req, &materialized, nil)
}

// ExecuteWithCredentialsStreaming combines the explicit credential boundary
// with live output delivery. Values enter only the CLI stdin pipe and the
// in-memory redacting sink; neither is persisted by this adapter.
func (d *DockerSandbox) ExecuteWithCredentialsStreaming(ctx context.Context, req SandboxRequest, materialized CredentialMaterialization, sink OutputSink) (SandboxResult, error) {
	return d.execute(ctx, req, &materialized, sink)
}

func (d *DockerSandbox) execute(ctx context.Context, req SandboxRequest, materialized *CredentialMaterialization, sink OutputSink) (SandboxResult, error) {
	if d == nil || !d.Profile().Valid() {
		return SandboxResult{ExitCode: -1, ErrorText: ErrRunnerUnavailable.Error()}, ErrRunnerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(req.Command) == "" || len(req.Command) > 8192 || strings.IndexFunc(req.Command, func(r rune) bool { return r == '\x00' }) >= 0 {
		return SandboxResult{ExitCode: -1, ErrorText: "invalid command"}, errors.New("commandrunner: invalid sandbox command")
	}
	if len(req.CredentialIDs) > 0 && materialized == nil {
		// The ordinary Sandbox interface is deliberately credential-free. A
		// caller must opt into ExecuteWithCredentials so secret delivery cannot
		// happen accidentally through an old adapter call site.
		return SandboxResult{ExitCode: -1, ErrorText: ErrCredentialBoundary.Error()}, ErrCredentialBoundary
	}
	if materialized != nil {
		defer materialized.Clear()
		if err := validateCredentialBindings(req.CredentialIDs, materialized.Bindings); err != nil {
			return SandboxResult{ExitCode: -1, ErrorText: ErrCredentialBoundary.Error()}, err
		}
	}
	workdir := req.WorkingDir
	if workdir == "" {
		workdir = "/workspace"
	}
	normalizedWorkdir, workdirErr := commandautomations.NormalizeWorkingDir(workdir)
	if workdirErr != nil {
		return SandboxResult{ExitCode: -1, ErrorText: "invalid container working directory"}, errors.New("commandrunner: unsafe container working directory")
	}
	workdir = normalizedWorkdir

	args := []string{
		"run", "--rm", "--init", "--pull=never", "--cidfile", "__CIDFILE__", "--network=none", "--read-only",
		"--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit", strconv.Itoa(d.pidsLimit),
		"--memory", strconv.FormatInt(d.memoryBytes, 10), "--cpus", d.cpus,
		"--user", "65532:65532", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + strconv.FormatInt(d.tmpfsBytes, 10),
		"--workdir", workdir, "--env", "REACTOR_MODE=command",
	}
	cidDir, err := os.MkdirTemp("", "reactor-command-")
	if err != nil {
		return SandboxResult{ExitCode: -1, ErrorText: "container cleanup setup failed"}, err
	}
	cidPath := filepath.Join(cidDir, "container.cid")
	defer os.RemoveAll(cidDir)
	if materialized != nil && len(materialized.Bindings) > 0 {
		// Docker opens env-file paths in the client process. On the supported
		// Unix hosts, /dev/stdin resolves to this child's stdin pipe. No
		// plaintext credential file is created on the host.
		args = append(args, "--env-file", "/dev/stdin")
	}
	args = append(args, d.image, "/bin/sh", "-c", req.Command)
	for i := range args {
		if args[i] == "__CIDFILE__" {
			args[i] = cidPath
			break
		}
	}
	cmd := exec.CommandContext(ctx, d.binary, args...)
	if materialized != nil && len(materialized.Bindings) > 0 {
		cmd.Stdin = credentialEnvReader(materialized.Bindings)
	}
	// Do not inherit operator credentials, proxy variables, or arbitrary PATH
	// entries into the Docker client process.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	// Capture one additional durable-cap window so the journal redactor can
	// complete a secret pattern that crosses the visible-output boundary while
	// retaining bounded memory. The journal persists only its first cap bytes.
	captureLimit := d.maxOutputBytes * 2
	stdout := &boundedCapture{limit: captureLimit}
	stderr := &boundedCapture{limit: captureLimit}
	if sink == nil {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	} else {
		cmd.Stdout = outputWriter{capture: stdout, sink: sink, stream: OutputStdout}
		cmd.Stderr = outputWriter{capture: stderr, sink: sink, stream: OutputStderr}
	}
	err = cmd.Run()
	// Killing the Docker CLI on a deadline can leave the container detached.
	// Resolve the cidfile and issue a bounded best-effort force removal before
	// returning; a cancellation without cleanup is never treated as success.
	if ctx.Err() != nil {
		cleanupDockerContainer(d.binary, cidPath)
	}
	result := SandboxResult{ExitCode: 0, Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), StdoutBytes: stdout.total, StderrBytes: stderr.total, StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		if ctx.Err() != nil {
			result.ErrorText = ctx.Err().Error()
			return result, ctx.Err()
		}
		// A normal non-zero exit is data, not a launch failure. Runner compares
		// it with the immutable expected_exit_code and journals the result.
		return result, nil
	}
	result.ExitCode = -1
	result.ErrorText = err.Error()
	return result, err
}

type outputWriter struct {
	capture *boundedCapture
	sink    OutputSink
	stream  OutputStream
}

func (w outputWriter) Write(p []byte) (int, error) {
	if w.capture != nil {
		_, _ = w.capture.Write(p)
	}
	if w.sink == nil {
		return len(p), nil
	}
	if err := w.sink.Write(w.stream, p); err != nil {
		return len(p), err
	}
	return len(p), nil
}

func validateCredentialBindings(ids []string, bindings []CredentialBinding) error {
	if len(ids) != len(bindings) {
		return ErrCredentialBoundary
	}
	seen := make(map[string]struct{}, len(bindings))
	for i, id := range ids {
		binding := bindings[i]
		if binding.CredentialID != id || binding.Environment != CredentialEnvironmentName(id) || len(binding.Value) == 0 || len(binding.Value) > vault.MaxSecretBytes || bytes.IndexByte(binding.Value, 0) >= 0 {
			return ErrCredentialBoundary
		}
		if _, ok := seen[binding.CredentialID]; ok {
			return ErrCredentialBoundary
		}
		seen[binding.CredentialID] = struct{}{}
		if !validCredentialEnvironment(binding.Environment) {
			return ErrCredentialBoundary
		}
		// Docker's env-file parser is line-oriented, requires UTF-8, and
		// uses a bounded scanner. Reject invalid input before the CLI can
		// emit a parser error containing any credential bytes.
		if bytes.Contains(binding.Value, []byte("\n")) || bytes.Contains(binding.Value, []byte("\r")) ||
			!utf8.Valid(binding.Value) || len(binding.Environment)+1+len(binding.Value)+1 >= bufio.MaxScanTokenSize {
			return ErrCredentialBoundary
		}
	}
	return nil
}

func validCredentialEnvironment(name string) bool {
	if len(name) == 0 || (name[0] < 'A' || name[0] > 'Z') && name[0] != '_' {
		return false
	}
	for _, r := range name[1:] {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func credentialEnvReader(bindings []CredentialBinding) io.Reader {
	readers := make([]io.Reader, 0, len(bindings)*3)
	for _, binding := range bindings {
		readers = append(readers,
			strings.NewReader(binding.Environment+"="),
			bytes.NewReader(binding.Value),
			strings.NewReader("\n"),
		)
	}
	return io.MultiReader(readers...)
}

func safeContainerWorkdir(raw string) bool {
	_, err := commandautomations.NormalizeWorkingDir(raw)
	return err == nil
}

func cleanupDockerContainer(binary, cidPath string) {
	raw, err := os.ReadFile(cidPath)
	if err != nil {
		return
	}
	id := strings.TrimSpace(string(raw))
	if !containerID.MatchString(id) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "rm", "-f", id)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	_ = cmd.Run()
}

type boundedCapture struct {
	buf       bytes.Buffer
	limit     int
	total     int
	truncated bool
}

func (b *boundedCapture) Write(p []byte) (int, error) {
	b.total += len(p)
	if b.limit <= 0 {
		b.truncated = len(p) > 0
		return len(p), nil
	}
	if b.buf.Len() < b.limit {
		remaining := b.limit - b.buf.Len()
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	// Returning len(p) prevents os/exec from terminating the child just
	// because the bounded audit capture reached its limit.
	return len(p), nil
}

func (b *boundedCapture) Bytes() []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b.buf.Bytes()...)
}
