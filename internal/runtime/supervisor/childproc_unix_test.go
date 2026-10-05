//go:build linux || darwin

package supervisor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestChildCancellationClosesDescendantOutputPipe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The background child inherits stdout. Killing only the shell would
	// leave the pipe open until sleep exits, blocking the supervisor decoder.
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 10 & echo ready; wait")
	configureChildProcess(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	}()
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("child start marker = %q, %v", line, err)
	}

	cancel()
	readDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, reader)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("forked workflow child kept stdout open after cancellation")
	}
}

func TestObserveAlreadyExitedChildWithoutReaping(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	time.Sleep(50 * time.Millisecond) // exercise registration after child exit
	done := make(chan error, 1)
	go func() { done <- observeChildExit(cmd.Process.Pid) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("observe already-exited child: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("exit observer missed child that exited before registration")
	}
}

func TestSupervisorProtocolErrorStopsForkedWorkflow(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_protocol_error_fork")
	defer cleanup()
	binary := filepath.Join(t.TempDir(), "invalid-workflow")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 10 &\nprintf 'invalid-frame\\n'\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sup.BinaryPath = binary
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		status string
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		status, err := sup.Run(ctx)
		done <- outcome{status, err}
	}()
	select {
	case got := <-done:
		if got.status != "failed" || got.err == nil {
			t.Fatalf("protocol failure outcome = %+v", got)
		}
		if run, err := j.GetRun(context.Background(), sup.RunID); err != nil || run.Status != "failed" {
			t.Fatalf("persisted protocol failure = %+v, %v", run, err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("forked workflow blocked supervisor after protocol failure")
	}
}

func TestSupervisorPanicReapsWorkflowBeforePersistingFailure(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_log_sink_panic_cleanup")
	defer cleanup()
	childPIDPath := filepath.Join(t.TempDir(), "child.pid")
	sup.ExtraEnv = append(sup.ExtraEnv, "FF_TEST_CHILD_PID_PATH="+childPIDPath)
	binary := filepath.Join(t.TempDir(), "log-then-wait")
	content := "#!/bin/sh\nIFS= read -r hello\necho $$ > \"$FF_TEST_CHILD_PID_PATH\"\nprintf '%s\\n' '{\"id\":1,\"kind\":\"log\",\"body\":{\"level\":\"info\",\"msg\":\"panic\"}}'\nsleep 10\n"
	if err := os.WriteFile(binary, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pidText, err := os.ReadFile(childPIDPath)
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(pidText))); err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	sup.BinaryPath = binary
	sup.LogSink = func(string, string) { panic("test log sink panic") }
	type outcome struct {
		status string
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		status, err := sup.Run(context.Background())
		done <- outcome{status, err}
	}()
	select {
	case got := <-done:
		if got.status != "failed" || got.err == nil || !strings.Contains(got.err.Error(), "test log sink panic") {
			t.Fatalf("panic outcome = %+v", got)
		}
		if run, err := j.GetRun(context.Background(), sup.RunID); err != nil || run.Status != "failed" {
			t.Fatalf("persisted panic outcome = %+v, %v", run, err)
		}
		pidText, err := os.ReadFile(childPIDPath)
		if err != nil {
			t.Fatalf("read workflow pid: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidText)))
		if err != nil {
			t.Fatalf("parse workflow pid: %v", err)
		}
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("recovered panic left workflow pid %d alive: %v", pid, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovered panic blocked while cleaning up workflow")
	}
}

func TestSupervisorDirectExitWithForkedOutputDoesNotHang(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spawn string
	}{
		{name: "stdout", spawn: "sleep 10 2>/dev/null &"},
		{name: "stderr", spawn: "sleep 10 >/dev/null &"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, j, cleanup := newTestSupervisorEnv(t, "run_exited_parent_fork_"+tc.name)
			defer cleanup()
			childPIDPath := filepath.Join(t.TempDir(), "child.pid")
			sup.ExtraEnv = append(sup.ExtraEnv, "FF_TEST_CHILD_PID_PATH="+childPIDPath)
			binary := filepath.Join(t.TempDir(), "fork-and-exit")
			content := "#!/bin/sh\nIFS= read -r hello\n" + tc.spawn + "\necho $! > \"$FF_TEST_CHILD_PID_PATH\"\nexit 0\n"
			if err := os.WriteFile(binary, []byte(content), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				pidText, err := os.ReadFile(childPIDPath)
				if err != nil {
					return
				}
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidText))); err == nil {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			})
			sup.BinaryPath = binary
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type outcome struct {
				status string
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				status, err := sup.Run(ctx)
				done <- outcome{status, err}
			}()
			select {
			case got := <-done:
				if got.status != "succeeded" || got.err != nil {
					t.Fatalf("cleaned up %s descendant outcome = %+v, want succeeded", tc.name, got)
				}
				if run, err := j.GetRun(context.Background(), sup.RunID); err != nil || run.Status != "succeeded" {
					t.Fatalf("persisted orphaned output outcome = %+v, %v", run, err)
				}
			case <-time.After(5 * time.Second):
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				t.Fatal("normal direct-process exit left supervisor blocked on descendant output")
			}
		})
	}
}

func TestSupervisorClosedProtocolOutputCannotRunForever(t *testing.T) {
	sup, j, cleanup := newTestSupervisorEnv(t, "run_closed_output_parent_alive")
	defer cleanup()
	binary := filepath.Join(t.TempDir(), "close-output-and-sleep")
	content := "#!/bin/sh\nIFS= read -r hello\nexec 1>&- 2>&-\nsleep 10\n"
	if err := os.WriteFile(binary, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	sup.BinaryPath = binary
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		status string
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		status, err := sup.Run(ctx)
		done <- outcome{status, err}
	}()
	select {
	case got := <-done:
		if got.status != "failed" || got.err == nil || !strings.Contains(got.err.Error(), "closed protocol output") {
			t.Fatalf("early output close outcome = %+v", got)
		}
		if run, err := j.GetRun(context.Background(), sup.RunID); err != nil || run.Status != "failed" {
			t.Fatalf("persisted early output close outcome = %+v, %v", run, err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("workflow continued running after closing protocol output")
	}
}
