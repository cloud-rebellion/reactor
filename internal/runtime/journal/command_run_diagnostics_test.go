package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestCommandDiagnosticPageIsExactBoundedAndTenantScoped(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	definition := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":30}]}`)
	plan, err := j.CreateCommandAutomation(ctx, "acme", "cmd_diag_page", "diag-page", "", "local", "alice", definition)
	if err != nil {
		t.Fatal(err)
	}
	enableCommandPlanForRun(t, j, ctx, plan)
	gate := sha256.Sum256([]byte("diag-page-gates"))
	admission := boundCommandRunAdmission(t, "acme", plan.ID, 1, definition, hex.EncodeToString(gate[:]), "alice")
	run, err := j.CreateCommandRun(ctx, "acme", "cmdrun_diag_page", plan.ID, 1, admission)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := j.ClaimCommandRun(ctx, run.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimCommandRunStep(ctx, run.ID, "worker-a", claimed.ClaimToken, 1); err != nil {
		t.Fatal(err)
	}
	stored := []byte{'A', 0, 0xc3, 0xa5, 0xe7, 0x95, 0x8c, 'Z'}
	if err := j.RecordCommandRunStepResult(ctx, run.ID, "worker-a", claimed.ClaimToken, 1, 1, 0, stored, nil, ""); err != nil {
		t.Fatal(err)
	}
	page, err := j.ReadCommandRunDiagnosticPageForTenant(ctx, "acme", run.ID, CommandDiagnosticStdout, 1, 1, 1, 3)
	if err != nil || !bytes.Equal(page.Content, stored[1:4]) || page.TotalBytes != len(stored) {
		t.Fatalf("page = %+v, err=%v", page, err)
	}
	if _, err := j.ReadCommandRunDiagnosticPageForTenant(ctx, "other", run.ID, CommandDiagnosticStdout, 1, 1, 0, 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant page error = %v", err)
	}
	if _, err := j.ReadCommandRunDiagnosticPageForTenant(ctx, "acme", run.ID, CommandDiagnosticStdout, 1, 2, 0, 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other attempt page error = %v", err)
	}
	if _, err := j.ReadCommandRunDiagnosticPageForTenant(ctx, "acme", run.ID, CommandDiagnosticStdout, 1, 1, 0, MaxCommandDiagnosticPageBytes+1); !errors.Is(err, ErrInvalidCommandDiagnosticPage) {
		t.Fatalf("oversized page error = %v", err)
	}
	if _, err := j.ReadCommandRunDiagnosticPageForTenant(ctx, "acme", run.ID, CommandDiagnosticRunError, 1, 1, 0, 3); !errors.Is(err, ErrInvalidCommandDiagnosticPage) {
		t.Fatalf("ambiguous parent source error = %v", err)
	}
}
