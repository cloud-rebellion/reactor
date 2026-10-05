package journal

// Regression tests for the per-run call ordinal (seq). Before it, the replay key
// was (run_id, step_name) with no ordinal, so a Step reused in a loop resolved
// every iteration to the FIRST iteration's row: the side effect ran once,
// iterations 2..N were served stale output, and the run reported succeeded. The
// audit reproduced a three-invoice loop that sent one invoice.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestFindCachedOutputForInputFiltersByHash(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// Seed a successful step row with input_hash h1.
	if _, err := j.RecordStepStart(ctx, "run_1", "fetch", 1, "k1", "h1"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEnd(ctx, "run_1", "fetch", 1, json.RawMessage(`{"v":1}`), ""); err != nil {
		t.Fatal(err)
	}

	// Same input_hash matches.
	got, err := j.FindCachedOutputForInput(ctx, "run_1", "fetch", "k1", "h1")
	if err != nil {
		t.Fatalf("matching hash: %v", err)
	}
	if string(got) != `{"v":1}` {
		t.Fatalf("matching hash got %s, want {\"v\":1}", got)
	}

	// Different input_hash returns ErrNotFound so the supervisor
	// re-executes (live) or trips ErrReplayDivergence (replay).
	if _, err := j.FindCachedOutputForInput(ctx, "run_1", "fetch", "k1", "h2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("drifted hash err = %v, want ErrNotFound", err)
	}

	// Empty input_hash falls back to ignoring the hash (legacy behaviour).
	if _, err := j.FindCachedOutputForInput(ctx, "run_1", "fetch", "k1", ""); err != nil {
		t.Fatalf("empty hash should match: %v", err)
	}
}

func TestHasCachedOutputAnyInput(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	any, err := j.HasCachedOutputAnyInput(ctx, "run_1", "fetch")
	if err != nil || any {
		t.Fatalf("before insert: any=%v err=%v, want false nil", any, err)
	}

	if _, err := j.RecordStepStart(ctx, "run_1", "fetch", 1, "k1", "h1"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEnd(ctx, "run_1", "fetch", 1, json.RawMessage(`{"v":1}`), ""); err != nil {
		t.Fatal(err)
	}

	any, err = j.HasCachedOutputAnyInput(ctx, "run_1", "fetch")
	if err != nil || !any {
		t.Fatalf("after insert: any=%v err=%v, want true nil", any, err)
	}
}

func TestDeleteWorkflowRefusesActiveRuns(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	// run_1 is in 'running' status from CreateRun in the fixture.
	if err := j.DeleteWorkflow(ctx, "wf_1"); !errors.Is(err, ErrWorkflowBusy) {
		t.Fatalf("delete with active run err = %v, want ErrWorkflowBusy", err)
	}

	// Move run to a terminal state.
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteWorkflow(ctx, "wf_1"); err != nil {
		t.Fatalf("delete after terminal: %v", err)
	}
}

func TestDeleteWorkflowIfDisabledRequiresAtomicPause(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.DeleteWorkflowIfDisabled(ctx, "wf_1"); !errors.Is(err, ErrWorkflowEnabled) {
		t.Fatalf("enabled delete err = %v, want ErrWorkflowEnabled", err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_1", false); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteWorkflowIfDisabled(ctx, "wf_1"); !errors.Is(err, ErrWorkflowBusy) {
		t.Fatalf("disabled workflow with active run err = %v, want ErrWorkflowBusy", err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteWorkflowIfDisabled(ctx, "wf_1"); err != nil {
		t.Fatalf("disabled terminal workflow delete: %v", err)
	}
}

// TestStepSeqSeparatesLoopIterations is the data-layer half of the loop fix.
// Three calls to one step name in a run must occupy three rows carrying three
// outputs. Keyed on (run_id, step_name, attempt) the second and third inserts
// hit the primary key and were silently discarded by ON CONFLICT DO NOTHING, so
// the run's journal claimed one execution where three happened.
func TestStepSeqSeparatesLoopIterations(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	for i := int64(1); i <= 3; i++ {
		inserted, err := j.RecordStepStartSeq(ctx, "run_1", "send-invoice", i, 1, "", "h")
		if err != nil {
			t.Fatalf("seq %d start: %v", i, err)
		}
		if !inserted {
			t.Fatalf("seq %d should insert its own row; the ordinal is what keeps loop iterations apart", i)
		}
		out := json.RawMessage(`"sent:INV-` + string(rune('0'+i)) + `"`)
		if err := j.RecordStepEndSeq(ctx, "run_1", "send-invoice", i, 1, out, ""); err != nil {
			t.Fatalf("seq %d end: %v", i, err)
		}
	}

	// Each ordinal must replay ITS OWN output, not the first iteration's.
	for i := int64(1); i <= 3; i++ {
		got, recorded, err := j.FindCachedOutputBySeq(ctx, "run_1", i)
		if err != nil {
			t.Fatalf("seq %d lookup: %v", i, err)
		}
		if recorded != "send-invoice" {
			t.Fatalf("seq %d recorded step = %q, want send-invoice", i, recorded)
		}
		want := `"sent:INV-` + string(rune('0'+i)) + `"`
		if string(got) != want {
			t.Fatalf("seq %d replayed %s, want %s (this is the stale-output bug)", i, got, want)
		}
	}
}

// TestFindCachedOutputBySeqSurfacesRecordedStepName pins the divergence signal.
// The supervisor compares the name recorded against an ordinal with the name the
// running workflow reached it as; a mismatch means program order changed across
// a resume, and serving the cache would attribute one step's result to another.
func TestFindCachedOutputBySeqSurfacesRecordedStepName(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.RecordStepStartSeq(ctx, "run_1", "alpha", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "alpha", 1, 1, json.RawMessage(`"a"`), ""); err != nil {
		t.Fatal(err)
	}
	_, recorded, err := j.FindCachedOutputBySeq(ctx, "run_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if recorded != "alpha" {
		t.Fatalf("recorded step = %q, want alpha: without it a renamed step replays silently", recorded)
	}

	// seq 0 means a pre-ordinal workflow binary and must never resolve here,
	// or legacy rows would be served against arbitrary ordinals.
	if _, _, err := j.FindCachedOutputBySeq(ctx, "run_1", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("seq 0 lookup = %v, want ErrNotFound", err)
	}
	// An ordinal the run never reached is simply not cached.
	if _, _, err := j.FindCachedOutputBySeq(ctx, "run_1", 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unreached ordinal = %v, want ErrNotFound", err)
	}
}

func TestFindCachedOutputBySeqForInputReturnsReplayIdentity(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.RecordStepStartSeq(ctx, "run_1", "send", 1, 1, "idem-v1", "hash-v1"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "send", 1, 1, json.RawMessage(`{"sent":true}`), ""); err != nil {
		t.Fatal(err)
	}
	out, step, idem, inputHash, err := j.FindCachedOutputBySeqForInput(ctx, "run_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"sent":true}` || step != "send" || idem != "idem-v1" || inputHash != "hash-v1" {
		t.Fatalf("ordinal cache identity = output=%s step=%q idem=%q hash=%q", out, step, idem, inputHash)
	}
}

func TestFindRecordedStepNameBySeqIncludesUnsuccessfulAttempts(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := j.RecordStepStartSeq(ctx, "run_1", "charge", 3, 1, "idem", "hash"); err != nil {
		t.Fatal(err)
	}
	// Leave the attempt running. The identity lookup must still report it;
	// there is intentionally no successful cache row to consult.
	name, err := j.FindRecordedStepNameBySeq(ctx, "run_1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if name != "charge" {
		t.Fatalf("recorded step = %q, want charge", name)
	}

	if _, err := j.FindRecordedStepNameBySeq(ctx, "run_1", 4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unreached ordinal err = %v, want ErrNotFound", err)
	}
}
