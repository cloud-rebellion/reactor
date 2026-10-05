package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
)

func TestWorkerParentLivenessGuardHelper(t *testing.T) {
	if os.Getenv("REACTOR_TEST_PARENT_GUARD_HELPER") != "1" {
		return
	}
	ctx, stop, err := workerContextWithParentLiveness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	fmt.Println("parent-guard-ready")
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), cancelreg.ErrInfrastructureShutdown) {
			t.Fatalf("parent EOF cause = %v", context.Cause(ctx))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parent pipe EOF did not cancel worker")
	}
}

func TestWorkerParentLivenessGuardDrainsOnParentEOF(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	processCtx, stopProcess := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopProcess()
	cmd := exec.CommandContext(processCtx, os.Args[0], "-test.run=^TestWorkerParentLivenessGuardHelper$")
	cmd.ExtraFiles = []*os.File{read}
	cmd.Env = append(os.Environ(), workerParentFDEnv+"=3", "REACTOR_TEST_PARENT_GUARD_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		read.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		read.Close()
		t.Fatal(err)
	}
	read.Close()
	ready, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || !strings.Contains(ready, "parent-guard-ready") {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("worker guard helper did not start: %q, %v", ready, err)
	}
	write.Close() // kernel EOF is what an abrupt parent exit delivers
	if err := cmd.Wait(); err != nil {
		t.Fatalf("worker did not drain after parent EOF: %v", err)
	}
}

func TestWorkerParentLivenessGuardRejectsInvalidDescriptor(t *testing.T) {
	t.Setenv(workerParentFDEnv, "9")
	if _, _, err := workerContextWithParentLiveness(context.Background()); err == nil {
		t.Fatal("invalid inherited descriptor was accepted")
	}
}

func TestWorkerRuntimeEnvDoesNotForwardParentPipeToDetachedWorkers(t *testing.T) {
	t.Setenv(workerParentFDEnv, "3")
	for _, entry := range workerRuntimeEnv("postgres://test", make([]byte, 32)) {
		if strings.HasPrefix(entry, workerParentFDEnv+"=") {
			t.Fatal("parent pipe marker escaped into a detached worker environment")
		}
	}
}
