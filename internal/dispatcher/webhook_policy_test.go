package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/webhookpolicy"
)

func TestWebhookExactVersionPolicyRefusesBeforeArtifactOrRun(t *testing.T) {
	for _, dag := range []string{
		`{"triggers":[{"kind":"webhook","provider":"flare-v1"}]}`,
		`{"triggers":[{"kind":"webhook","provider":"generic"},{"kind":"webhook","provider":"flare-v1"}]}`,
		`{"triggers":null}`,
		`{"triggers":`,
		`{"padding":"` + strings.Repeat("x", webhookpolicy.MaxDAGBytes) + `"}`,
	} {
		j := newJournal(t)
		if err := j.CreateWorkflowWithArtifact(context.Background(), "wf_policy", "policy", "source", "1", testArtifactSHA256, json.RawMessage(dag)); err != nil {
			t.Fatal(err)
		}
		lookups := 0
		d := &Dispatcher{Journal: j, Resolver: &SQLResolver{Journal: j}, Enqueue: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ArtifactPath: func(string, string) (string, error) { lookups++; return "/must-not-execute", nil }}
		if id, err := d.DispatchWebhook(context.Background(), journal.Trigger{WorkflowID: "wf_policy", Kind: journal.TriggerWebhook, Provider: "generic"}, []byte(`{}`)); id != "" || !errors.Is(err, webhookpolicy.ErrPolicy) || lookups != 0 {
			t.Fatalf("policy escaped before-effects fence: id=%q err=%v lookups=%d", id, err, lookups)
		}
		if runs, err := j.ListRecentRuns(context.Background(), 10); err != nil || len(runs) != 0 {
			t.Fatalf("policy refusal persisted runs: %+v %v", runs, err)
		}
	}
}

func TestWebhookPolicyDoesNotGateIndependentManualOrCronRuns(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	// An invalid webhook policy is irrelevant to explicitly independent cron
	// and manual entry points; those retain their existing authorization gates.
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_independent", "independent", "source", "1", testArtifactSHA256, json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"unsupported"}]}`)); err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{Journal: j, Resolver: &SQLResolver{Journal: j}, Enqueue: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ArtifactPath: func(string, string) (string, error) { return "/unused-queued-artifact", nil }}
	for _, kind := range []journal.TriggerKind{journal.TriggerManual, journal.TriggerCron} {
		if err := d.Dispatch(ctx, journal.Trigger{WorkflowID: "wf_independent", Kind: kind}, []byte(`{}`)); err != nil {
			t.Fatalf("independent %s dispatch was blocked: %v", kind, err)
		}
	}
	if runs, err := j.ListRecentRuns(ctx, 10); err != nil || len(runs) != 2 {
		t.Fatalf("independent runs=%+v %v", runs, err)
	}
}

func TestWebhookSelectedVersionRemainsPinnedAcrossLaterPolicyPublication(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_selected", "selected", "old", "1", testArtifactSHA256, json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"generic"}]}`)); err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{Journal: j, Resolver: &SQLResolver{Journal: j}, Enqueue: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d.ArtifactPath = func(string, string) (string, error) {
		// The immutable generic version was already selected and validated.
		// Publishing a later Flare version cannot replace those run pins.
		_, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_selected", "1", "new", strings.Repeat("b", 64), json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"flare-v1"}]}`))
		return "/unused-queued-artifact", err
	}
	id, err := d.DispatchWebhook(ctx, journal.Trigger{WorkflowID: "wf_selected", Kind: journal.TriggerWebhook, Provider: "generic"}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	run, err := j.GetRun(ctx, id)
	if err != nil || run.WorkflowVersion != 1 || run.WorkflowArtifactSHA256 != testArtifactSHA256 || run.TriggerKind != string(journal.TriggerWebhook) {
		t.Fatalf("publication replaced selected run provenance: %+v %v", run, err)
	}
}
