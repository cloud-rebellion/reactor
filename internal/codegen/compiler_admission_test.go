package codegen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type cancelWhenSelectingCompilerSlot struct {
	context.Context
	cancel context.CancelFunc
}

func (c cancelWhenSelectingCompilerSlot) Done() <-chan struct{} {
	c.cancel()
	return c.Context.Done()
}

func waitForCompilerQueue(t *testing.T, a *compilerAdmission, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(a.waiting) != want {
		if time.Now().After(deadline) {
			t.Fatalf("compiler queue length = %d, want %d", len(a.waiting), want)
		}
		runtime.Gosched()
	}
}

func TestCompilerAdmissionBoundsConcurrentJobsAndReleasesCancelledWaiter(t *testing.T) {
	a := newCompilerAdmission(1, 1)
	releaseActive, err := a.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	waitResult := make(chan error, 1)
	go func() {
		release, err := a.acquire(ctx)
		if release != nil {
			release()
		}
		waitResult <- err
	}()
	waitForCompilerQueue(t, a, 1)
	if _, err := a.acquire(context.Background()); !errors.Is(err, ErrCompilerBusy) {
		t.Fatalf("overflow admission = %v, want ErrCompilerBusy", err)
	}
	cancel()
	if err := <-waitResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter = %v", err)
	}
	waitForCompilerQueue(t, a, 0)
	releaseActive()
	release, err := a.acquire(context.Background())
	if err != nil {
		t.Fatalf("compiler slot leaked after cancellation: %v", err)
	}
	release()
}

func TestCompilerAdmissionDoesNotAdmitCancellationAtSlotHandoff(t *testing.T) {
	a := newCompilerAdmission(1, 1)
	for i := 0; i < 32; i++ {
		base, cancel := context.WithCancel(context.Background())
		ctx := cancelWhenSelectingCompilerSlot{Context: base, cancel: cancel}
		release, err := a.acquire(ctx)
		if release != nil || !errors.Is(err, context.Canceled) || len(a.active) != 0 || len(a.waiting) != 0 {
			t.Fatalf("cancelled request took a compiler slot: release=%v err=%v active=%d waiting=%d", release != nil, err, len(a.active), len(a.waiting))
		}
	}
}

func TestCompilerAdmissionSharedByValidateAndRegister(t *testing.T) {
	previous := workflowCompilerAdmission
	a := newCompilerAdmission(1, 1)
	workflowCompilerAdmission = a
	t.Cleanup(func() { workflowCompilerAdmission = previous })
	a.waiting <- struct{}{} // Fill the bounded queue without invoking Go.
	if err := ValidateWorkflowSource(context.Background(), ValidateSourceRequest{
		Slug: "busy-validation", MainGo: "package main\nfunc main() {}\n",
	}); !errors.Is(err, ErrCompilerBusy) {
		t.Fatalf("validation admission = %v, want ErrCompilerBusy", err)
	}
	if err := (&GoBuildValidator{}).Validate(context.Background(), t.TempDir(), EmitInput{Slug: "busy-generator"}); !errors.Is(err, ErrCompilerBusy) {
		t.Fatalf("generator validation admission = %v, want ErrCompilerBusy", err)
	}
	j := &fakeJournal{}
	if _, err := BuildAndRegister(context.Background(), j, BuildAndRegisterRequest{
		Slug: "busy-registration", SrcDir: t.TempDir(), StateRoot: t.TempDir(),
	}); !errors.Is(err, ErrCompilerBusy) {
		t.Fatalf("registration admission = %v, want ErrCompilerBusy", err)
	}
	if j.createdID != "" || j.recordedID != "" {
		t.Fatalf("busy registration touched journal: %+v", j)
	}
	<-a.waiting
	// The public preflight owns one slot across module setup and its nested
	// validator. With capacity one, reacquiring inside the validator would
	// block until the request's own context ended.
	validationCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ValidateWorkflowSource(validationCtx, ValidateSourceRequest{
		Slug: "admitted-validation", MainGo: "package main\nfunc main() {}\n",
	}); err != nil {
		t.Fatalf("nested validator did not reuse admission: %v", err)
	}
}

func TestBuildAndRegisterSourceBusyBeforeStaging(t *testing.T) {
	previous := workflowCompilerAdmission
	a := newCompilerAdmission(1, 1)
	workflowCompilerAdmission = a
	t.Cleanup(func() { workflowCompilerAdmission = previous })
	a.waiting <- struct{}{}
	stagingRoot := t.TempDir()
	stateRoot := filepath.Join(t.TempDir(), "state")
	t.Setenv("TMPDIR", stagingRoot)
	j := &fakeJournal{}
	req := BuildSourceRequest{
		Slug: "busy-source", MainGo: "package main\nfunc main() {}\n",
		StateRoot: stateRoot,
	}
	res, err := BuildAndRegisterSource(context.Background(), j, req)
	if !errors.Is(err, ErrCompilerBusy) || res.WorkflowID != "" {
		t.Fatalf("busy source registration = result:%+v err:%v", res, err)
	}
	if entries, err := os.ReadDir(stagingRoot); err != nil || len(entries) != 0 {
		t.Fatalf("busy request staged source: entries=%v err=%v", entries, err)
	}
	if _, err := os.Stat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("busy request touched workflow state: %v", err)
	}
	if j.createdID != "" || j.recordedID != "" {
		t.Fatalf("busy request touched journal: %+v", j)
	}
	<-a.waiting
	// One admitted source build must reuse its lease in BuildAndRegister.
	// Otherwise capacity one would deadlock at the nested registration call.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err = BuildAndRegisterSource(ctx, j, req)
	if err != nil || res.WorkflowID == "" {
		t.Fatalf("admitted source build failed to reuse compiler slot: result=%+v err=%v", res, err)
	}
}
