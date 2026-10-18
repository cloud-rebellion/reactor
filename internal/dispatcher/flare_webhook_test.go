package dispatcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestFlareWebhookRunIdentityCannotAdoptManualRun(t *testing.T) {
	ctx := context.Background()
	j := newJournal(t)
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	artifact, err := reg.PublishArtifact("flare-provenance", artifactScript(t, filepath.Join(t.TempDir(), "marker"), "unused"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowWithArtifact(ctx, "wf_flare_provenance", "flare-provenance", "source", "1", artifact.Digest, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{Journal: j, Resolver: &SQLResolver{Journal: j}, ArtifactPath: reg.ArtifactPath, Enqueue: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	trigger := journal.Trigger{ID: "trg_flare_provenance", WorkflowID: "wf_flare_provenance", Kind: journal.TriggerWebhook, Provider: "flare-v1"}
	body := []byte(`{"schema":"flare.automation.v1","event":"new_issue","project_id":"project-1","issue_id":"issue-1","event_count":1,"observed_at":"2026-10-18T15:00:00Z"}`)
	// Authenticated MCP users choose their manual retry key. Even knowing the
	// receiver's deterministic namespace must not turn their run into proof of
	// an authenticated Flare webhook invocation.
	h := sha256.New()
	for _, value := range []string{trigger.ID, trigger.WorkflowID, trigger.Provider} {
		h.Write([]byte(value))
		h.Write([]byte{0})
	}
	h.Write(body)
	key := "flare-webhook-" + hex.EncodeToString(h.Sum(nil))
	manual := trigger
	manual.Kind = journal.TriggerManual
	manualID, err := d.DispatchManualIdempotent(ctx, manual, body, key)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := d.DispatchWebhook(ctx, trigger, body); !errors.Is(err, journal.ErrMCPDispatchIdempotencyConflict) || id != "" {
		t.Fatalf("manual receipt adopted as Flare webhook: %s %v", id, err)
	}
	row, err := j.GetRun(ctx, manualID)
	if err != nil || row.TriggerKind != string(journal.TriggerManual) {
		t.Fatalf("manual provenance changed=%+v %v", row, err)
	}
}
