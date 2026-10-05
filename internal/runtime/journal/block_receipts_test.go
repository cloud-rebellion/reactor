package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBlockReceiptBindsTenantRunningAttemptAndBounds(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	artifact := strings.Repeat("a", 64)
	dag := json.RawMessage(`{"steps":[{"name":"merge-step","kind":"step","visual_flow":{"blocks":[{"id":"join","kind":"merge","mode":"full_join","max_rows":10}],"edges":[]}}]}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_observed", "observed", "h", "0.1.0", artifact, dag, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, "run_observed", "wf_observed", "manual", json.RawMessage(`{"customer":"private"}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_observed", "merge-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	item := BlockReceipt{RunID: "run_observed", StepName: "merge-step", Seq: 1, Attempt: 1, CallOrdinal: 1,
		BlockID: "join", Kind: "merge", Mode: "full_join", LeftRows: 2, RightRows: 3,
		OutputRows: 4, MaxRows: 10, Outcome: "succeeded"}
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendBlockReceipt(ctx, "globex", "", item); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign append = %v", err)
	}
	if err := j.AppendBlockReceipt(ctx, "acme", "stale-worker/generation", item); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("unowned append = %v", err)
	}
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); err == nil {
		t.Fatal("duplicate call ordinal replaced an existing receipt")
	}
	bad := item
	bad.CallOrdinal = 2
	bad.LeftRows = 100001
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); err == nil {
		t.Fatal("oversized row count accepted")
	}
	bad = item
	bad.CallOrdinal = 2
	bad.StepName = "missing-step"
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unclaimed step append = %v", err)
	}
	item.CallOrdinal = 2
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_observed", "merge-step", 1, 1, json.RawMessage(`null`), "retry"); err != nil {
		t.Fatal(err)
	}
	item.CallOrdinal = 3
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished attempt append = %v", err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_observed", "merge-step", 1, 2, "", "h"); err != nil {
		t.Fatal(err)
	}
	item.Attempt, item.CallOrdinal, item.Outcome, item.OutputRows = 2, 1, "bounded_failure", 0
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); err != nil {
		t.Fatal(err)
	}
	page, more, err := j.ListBlockReceiptsForTenant(ctx, "run_observed", "acme", 2, 0)
	if err != nil || !more || len(page) != 2 || page[0].Attempt != 2 || page[1].CallOrdinal != 2 {
		t.Fatalf("page = %+v, more=%v, err=%v", page, more, err)
	}
	foreign, more, err := j.ListBlockReceiptsForTenant(ctx, "run_observed", "globex", 10, 0)
	if err != nil || more || len(foreign) != 0 {
		t.Fatalf("foreign page = %+v, more=%v, err=%v", foreign, more, err)
	}
	ids, err := j.ObservedBlockIdentitiesForTenant(ctx, "run_observed", "acme")
	if err != nil || len(ids) != 1 || ids[0].BlockID != "join" {
		t.Fatalf("observed identities = %+v, %v", ids, err)
	}
	foreignIDs, err := j.ObservedBlockIdentitiesForTenant(ctx, "run_observed", "globex")
	if err != nil || len(foreignIDs) != 0 {
		t.Fatalf("foreign identities = %+v, %v", foreignIDs, err)
	}
}

func TestSplitReceiptStoresTypedCountsWithinTenantAndLiveAttempt(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	artifact := strings.Repeat("b", 64)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_split_receipt", "split-receipt", "h", "0.1.0", artifact,
		json.RawMessage(`{"steps":[{"name":"route-step","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, "run_split_receipt", "wf_split_receipt", "manual", json.RawMessage(`{}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_split_receipt", "route-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	input, yes, no := 3, 1, 2
	item := BlockReceipt{RunID: "run_split_receipt", StepName: "route-step", Seq: 1, Attempt: 1,
		CallOrdinal: 1, BlockID: "route", Kind: "split", InputRows: &input, YesRows: &yes,
		NoRows: &no, Outcome: "succeeded"}
	if err := j.AppendBlockReceipt(ctx, "globex", "", item); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant append = %v", err)
	}
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); err != nil {
		t.Fatal(err)
	}
	bad := item
	bad.CallOrdinal = 2
	bad.NoRows = &yes
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); err == nil {
		t.Fatal("inconsistent branch counts accepted")
	}
	bad = item
	bad.CallOrdinal = 2
	bad.MaxRows = 10
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); err == nil {
		t.Fatal("split receipt mixed with merge bound")
	}
	bad = item
	bad.CallOrdinal = 2
	bad.Attempt = 2
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unclaimed attempt append = %v", err)
	}
	page, more, err := j.ListBlockReceiptsForTenant(ctx, item.RunID, "acme", 10, 0)
	if err != nil || more || len(page) != 1 || page[0].InputRows == nil || *page[0].InputRows != 3 ||
		page[0].YesRows == nil || *page[0].YesRows != 1 || page[0].NoRows == nil || *page[0].NoRows != 2 {
		t.Fatalf("typed split page = %+v, more=%v, err=%v", page, more, err)
	}
	foreign, _, err := j.ListBlockReceiptsForTenant(ctx, item.RunID, "globex", 10, 0)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign split page = %+v, %v", foreign, err)
	}
}

func TestObservedCollectionReceiptsKeepTypedCountsAndLiveAttempt(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	artifact := strings.Repeat("c", 64)
	dag := json.RawMessage(`{"steps":[{"name":"collection-step","kind":"step","visual_flow":{"blocks":[{"id":"each","kind":"iterate"},{"id":"sum","kind":"aggregate"}]}}]}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_collection_receipt", "collection-receipt", "h", "0.1.0", artifact, dag, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, "run_collection_receipt", "wf_collection_receipt", "manual", json.RawMessage(`{"secret":"private-value"}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_collection_receipt", "collection-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	input := 2
	iterate := BlockReceipt{RunID: "run_collection_receipt", StepName: "collection-step", Seq: 1, Attempt: 1,
		CallOrdinal: 1, BlockID: "each", Kind: "iterate", InputRows: &input, OutputRows: 2, Outcome: "succeeded"}
	if err := j.AppendBlockReceipt(ctx, "globex", "", iterate); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign append = %v", err)
	}
	if err := j.AppendBlockReceipt(ctx, "acme", "", iterate); err != nil {
		t.Fatal(err)
	}
	aggregate := iterate
	aggregate.BlockID, aggregate.Kind, aggregate.CallOrdinal, aggregate.OutputRows = "sum", "aggregate", 2, 1
	if err := j.AppendBlockReceipt(ctx, "acme", "", aggregate); err != nil {
		t.Fatal(err)
	}
	bad := iterate
	bad.CallOrdinal, bad.OutputRows = 3, 1
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); err == nil {
		t.Fatal("inconsistent iterate count accepted")
	}
	bad = aggregate
	bad.CallOrdinal, bad.OutputRows = 3, 2
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); err == nil {
		t.Fatal("aggregate with two outputs accepted")
	}
	bad = aggregate
	bad.CallOrdinal, bad.YesRows = 3, &input
	if err := j.AppendBlockReceipt(ctx, "acme", "", bad); err == nil {
		t.Fatal("aggregate with branch count accepted")
	}
	// The database must reject forged protocol rows even when the Go shape
	// guard is bypassed by an old or faulty writer.
	const invalidSQL = `INSERT INTO run_block_receipts
		(run_id, step_name, seq, attempt, call_ordinal, block_id, kind, mode,
		 left_rows, right_rows, output_rows, max_rows, input_rows, outcome)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	if _, err := j.db.ExecContext(ctx, j.bind(invalidSQL), iterate.RunID, iterate.StepName,
		1, 1, 3, "each", "iterate", "", 0, 0, 1, 0, 2, "succeeded"); err == nil {
		t.Fatal("database accepted inconsistent iterate count")
	}
	page, more, err := j.ListBlockReceiptsForTenant(ctx, iterate.RunID, "acme", 10, 0)
	if err != nil || more || len(page) != 2 || page[0].Kind != "aggregate" || page[0].InputRows == nil ||
		*page[0].InputRows != 2 || page[0].OutputRows != 1 || page[1].Kind != "iterate" || page[1].OutputRows != 2 {
		t.Fatalf("typed collection page = %+v, more=%v, err=%v", page, more, err)
	}
	if err := j.RecordStepEndSeq(ctx, iterate.RunID, "collection-step", 1, 1, json.RawMessage(`null`), ""); err != nil {
		t.Fatal(err)
	}
	iterate.CallOrdinal = 3
	if err := j.AppendBlockReceipt(ctx, "acme", "", iterate); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished step accepted collection receipt: %v", err)
	}
}

func TestBlockReceiptRejectsExpiredAndReplacedLeaseGeneration(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflow(ctx, "wf_receipt_lease", "receipt-lease", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateQueuedRun(ctx, "run_receipt_lease", "wf_receipt_lease", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	claims, err := j.ClaimQueuedRuns(ctx, "worker-a", 1, time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = %+v, %v", claims, err)
	}
	owner := claims[0].Owner
	if _, err := j.RecordStepStartSeq(ctx, "run_receipt_lease", "merge-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	item := BlockReceipt{RunID: "run_receipt_lease", StepName: "merge-step", Seq: 1, Attempt: 1, CallOrdinal: 1,
		BlockID: "join", Kind: "merge", Mode: "inner_join", LeftRows: 1, RightRows: 1,
		OutputRows: 1, MaxRows: 10, Outcome: "succeeded"}
	if err := j.AppendBlockReceipt(ctx, DefaultTenant, owner, item); err != nil {
		t.Fatalf("live owner receipt: %v", err)
	}
	item.CallOrdinal = 2
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE leases SET expires_at = $1 WHERE run_id = $2`),
		j.formatTime(time.Now().UTC().Add(-time.Second)), item.RunID); err != nil {
		t.Fatal(err)
	}
	if err := j.AppendBlockReceipt(ctx, DefaultTenant, owner, item); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("expired owner receipt = %v", err)
	}
	if _, err := j.ReapExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := j.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].Owner == owner {
		t.Fatalf("replacement = %+v, %v", second, err)
	}
	if err := j.AppendBlockReceipt(ctx, DefaultTenant, owner, item); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("replaced owner receipt = %v", err)
	}
	page, _, err := j.ListBlockReceiptsForTenant(ctx, item.RunID, DefaultTenant, 10, 0)
	if err != nil || len(page) != 1 || page[0].CallOrdinal != 1 {
		t.Fatalf("fenced receipts = %+v, %v", page, err)
	}
}
