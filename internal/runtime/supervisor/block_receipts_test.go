package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
)

func TestObservedMergeReceiptRequiresPinnedDeclarationAndLiveAttempt(t *testing.T) {
	ctx := context.Background()
	sup, j, db, cleanup := newTestSupervisorEnvWithDB(t, "run_unused_observation")
	defer cleanup()
	const runID = "run_observed_supervisor"
	// This is a valid DAG under the 1 MiB authoring bound but above the old
	// 256 KiB supervisor cap. Accepted workflows must remain runnable.
	dag := []byte(`{"steps":[{"name":"merge-step","kind":"step","visual_flow":{"blocks":[{"id":"join","kind":"merge","mode":"full_join","key":"customer_id","max_rows":10}]}}]}` + strings.Repeat(" ", 300<<10))
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_observed_supervisor", "observed-supervisor", "h", "0.1.0", supervisorTestArtifactSHA256, json.RawMessage(dag), journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, runID, "wf_observed_supervisor", "manual", json.RawMessage(`{}`), 1, supervisorTestArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, runID, "merge-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	sup.RunID = runID
	base := wire.BlockReceipt{StepName: "merge-step", Seq: 1, Attempt: 1, CallOrdinal: 1,
		BlockID: "join", Kind: "merge", Mode: "full_join", LeftRows: 1, RightRows: 1,
		OutputRows: 1, MaxRows: 10, Outcome: "succeeded"}
	invoke := func(body wire.BlockReceipt) (string, error) {
		t.Helper()
		var output bytes.Buffer
		d := &dispatcher{sup: sup, enc: wire.NewEncoder(&output), writeMu: &sync.Mutex{}}
		f, err := wire.Wrap(1, 0, wire.KindBlockReceipt, body)
		if err != nil {
			t.Fatal(err)
		}
		err = d.handleBlockReceipt(ctx, f)
		return output.String(), err
	}
	for _, tc := range []struct {
		name string
		edit func(*wire.BlockReceipt)
	}{
		{"wrong block id", func(b *wire.BlockReceipt) { b.BlockID = "other" }},
		{"wrong mode", func(b *wire.BlockReceipt) { b.Mode = "left_join" }},
		{"wrong bound", func(b *wire.BlockReceipt) { b.MaxRows = 9 }},
		{"wrong step", func(b *wire.BlockReceipt) { b.StepName = "other-step" }},
		{"stale attempt", func(b *wire.BlockReceipt) { b.Attempt = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := base
			tc.edit(&body)
			if output, err := invoke(body); err == nil || output != "" {
				t.Fatalf("invalid observed receipt acknowledged: output=%q err=%v", output, err)
			}
		})
	}
	sup.Mode = "replay"
	if output, err := invoke(base); err == nil || output != "" {
		t.Fatalf("replay receipt acknowledged: output=%q err=%v", output, err)
	}
	sup.Mode = "live"
	if output, err := invoke(base); err != nil || !strings.Contains(output, `"kind":"ack"`) {
		t.Fatalf("valid large-DAG receipt = output %q, err %v", output, err)
	}
	if output, err := invoke(base); err == nil || output != "" {
		t.Fatalf("duplicate receipt acknowledged: output=%q err=%v", output, err)
	}
	page, _, err := j.ListBlockReceiptsForTenant(ctx, runID, journal.DefaultTenant, 10, 0)
	if err != nil || len(page) != 1 || page[0].BlockID != "join" {
		t.Fatalf("persisted receipt = %+v, %v", page, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE runs SET workflow_artifact_sha256 = ? WHERE id = ?`, strings.Repeat("f", 64), runID); err != nil {
		t.Fatal(err)
	}
	second := base
	second.CallOrdinal = 2
	if output, err := invoke(second); err == nil || output != "" {
		t.Fatalf("pin-drift receipt acknowledged: output=%q err=%v", output, err)
	}
}

func TestObservedSplitReceiptRequiresPinnedDeclarationAndLiveAttempt(t *testing.T) {
	ctx := context.Background()
	sup, j, db, cleanup := newTestSupervisorEnvWithDB(t, "run_unused_split_observation")
	defer cleanup()
	const runID = "run_observed_split_supervisor"
	dag := json.RawMessage(`{"steps":[{"name":"route-step","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_observed_split_supervisor", "observed-split-supervisor", "h", "0.1.0", supervisorTestArtifactSHA256, dag, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, runID, "wf_observed_split_supervisor", "manual", json.RawMessage(`{}`), 1, supervisorTestArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, runID, "route-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	sup.RunID = runID
	input, yes, no := 3, 1, 2
	base := wire.BlockReceipt{StepName: "route-step", Seq: 1, Attempt: 1, CallOrdinal: 1,
		BlockID: "route", Kind: "split", InputRows: &input, YesRows: &yes, NoRows: &no, Outcome: "succeeded"}
	invoke := func(body wire.BlockReceipt) (string, error) {
		t.Helper()
		var output bytes.Buffer
		d := &dispatcher{sup: sup, enc: wire.NewEncoder(&output), writeMu: &sync.Mutex{}}
		f, err := wire.Wrap(1, 0, wire.KindBlockReceipt, body)
		if err != nil {
			t.Fatal(err)
		}
		err = d.handleBlockReceipt(ctx, f)
		return output.String(), err
	}
	for _, tc := range []struct {
		name string
		edit func(*wire.BlockReceipt)
	}{
		{"wrong block id", func(b *wire.BlockReceipt) { b.BlockID = "other" }},
		{"wrong kind", func(b *wire.BlockReceipt) { b.Kind = "merge" }},
		{"wrong counts", func(b *wire.BlockReceipt) { b.NoRows = &yes }},
		{"stale attempt", func(b *wire.BlockReceipt) { b.Attempt = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := base
			tc.edit(&body)
			if output, err := invoke(body); err == nil || output != "" {
				t.Fatalf("invalid split receipt acknowledged: output=%q err=%v", output, err)
			}
		})
	}
	sup.Mode = "replay"
	if output, err := invoke(base); err == nil || output != "" {
		t.Fatalf("replay split acknowledged: output=%q err=%v", output, err)
	}
	sup.Mode = "live"
	if output, err := invoke(base); err != nil || !strings.Contains(output, `"kind":"ack"`) {
		t.Fatalf("valid split receipt = output %q, err %v", output, err)
	}
	if output, err := invoke(base); err == nil || output != "" {
		t.Fatalf("duplicate split receipt acknowledged: output=%q err=%v", output, err)
	}
	page, _, err := j.ListBlockReceiptsForTenant(ctx, runID, journal.DefaultTenant, 10, 0)
	if err != nil || len(page) != 1 || page[0].InputRows == nil || *page[0].InputRows != 3 {
		t.Fatalf("persisted split receipt = %+v, %v", page, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE runs SET workflow_artifact_sha256 = ? WHERE id = ?`, strings.Repeat("f", 64), runID); err != nil {
		t.Fatal(err)
	}
	second := base
	second.CallOrdinal = 2
	if output, err := invoke(second); err == nil || output != "" {
		t.Fatalf("artifact-drift split acknowledged: output=%q err=%v", output, err)
	}
}

func TestObservedCollectionReceiptRequiresExactPinnedBlockAndLiveAttempt(t *testing.T) {
	ctx := context.Background()
	sup, j, db, cleanup := newTestSupervisorEnvWithDB(t, "run_unused_collection_observation")
	defer cleanup()
	const runID = "run_observed_collection_supervisor"
	dag := json.RawMessage(`{"steps":[{"name":"collection-step","kind":"step","visual_flow":{"blocks":[{"id":"each","kind":"iterate"},{"id":"sum","kind":"aggregate"}]}}]}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_observed_collection_supervisor", "observed-collection-supervisor", "h", "0.1.0", supervisorTestArtifactSHA256, dag, journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, runID, "wf_observed_collection_supervisor", "manual", json.RawMessage(`{}`), 1, supervisorTestArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, runID, "collection-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	sup.RunID = runID
	input := 2
	base := wire.BlockReceipt{StepName: "collection-step", Seq: 1, Attempt: 1, CallOrdinal: 1,
		BlockID: "each", Kind: "iterate", InputRows: &input, OutputRows: 2, Outcome: "succeeded"}
	invoke := func(body wire.BlockReceipt) (string, error) {
		t.Helper()
		var output bytes.Buffer
		d := &dispatcher{sup: sup, enc: wire.NewEncoder(&output), writeMu: &sync.Mutex{}}
		f, err := wire.Wrap(1, 0, wire.KindBlockReceipt, body)
		if err != nil {
			t.Fatal(err)
		}
		err = d.handleBlockReceipt(ctx, f)
		return output.String(), err
	}
	for _, tc := range []struct {
		name string
		edit func(*wire.BlockReceipt)
	}{
		{"wrong block id", func(b *wire.BlockReceipt) { b.BlockID = "other" }},
		{"wrong declared kind", func(b *wire.BlockReceipt) { b.Kind = "aggregate"; b.OutputRows = 1 }},
		{"wrong count", func(b *wire.BlockReceipt) { b.OutputRows = 1 }},
		{"stale attempt", func(b *wire.BlockReceipt) { b.Attempt = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := base
			tc.edit(&body)
			if output, err := invoke(body); err == nil || output != "" {
				t.Fatalf("invalid collection receipt acknowledged: output=%q err=%v", output, err)
			}
		})
	}
	sup.Mode = "replay"
	if output, err := invoke(base); err == nil || output != "" {
		t.Fatalf("replay collection receipt acknowledged: output=%q err=%v", output, err)
	}
	sup.Mode = "live"
	if output, err := invoke(base); err != nil || !strings.Contains(output, `"kind":"ack"`) {
		t.Fatalf("valid iterate receipt = output %q, err %v", output, err)
	}
	aggregate := base
	aggregate.BlockID, aggregate.Kind, aggregate.CallOrdinal, aggregate.OutputRows = "sum", "aggregate", 2, 1
	if output, err := invoke(aggregate); err != nil || !strings.Contains(output, `"kind":"ack"`) {
		t.Fatalf("valid aggregate receipt = output %q, err %v", output, err)
	}
	page, _, err := j.ListBlockReceiptsForTenant(ctx, runID, journal.DefaultTenant, 10, 0)
	if err != nil || len(page) != 2 || page[0].Kind != "aggregate" || page[1].Kind != "iterate" {
		t.Fatalf("persisted collection receipts = %+v, %v", page, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE runs SET workflow_artifact_sha256 = ? WHERE id = ?`, strings.Repeat("f", 64), runID); err != nil {
		t.Fatal(err)
	}
	aggregate.CallOrdinal = 3
	if output, err := invoke(aggregate); err == nil || output != "" {
		t.Fatalf("artifact-drift collection receipt acknowledged: output=%q err=%v", output, err)
	}
}
