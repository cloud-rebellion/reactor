package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestHTTPMCPObservedMergeReceiptsAreTenantScopedBoundedAndValueFree(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	artifact := strings.Repeat("a", 64)
	dag := json.RawMessage(`{"steps":[{"name":"merge-step","kind":"step","visual_flow":{"blocks":[{"id":"join","kind":"merge","mode":"full_join","key":"customer_id","max_rows":10},{"id":"other","kind":"merge","mode":"full_join","key":"customer_id","max_rows":10},{"id":"append","kind":"merge","mode":"append"},{"id":"split","kind":"split"},{"id":"iterate","kind":"iterate"},{"id":"aggregate","kind":"aggregate"}]}}]}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_mcp_observed", "mcp-observed", "h", "0.1.0", artifact, dag, "acme"); err != nil {
		t.Fatal(err)
	}
	const secret = "private-customer-row-and-key"
	if err := j.CreateRunPinned(ctx, "run_mcp_observed", "wf_mcp_observed", "manual", json.RawMessage(`{"value":"`+secret+`"}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_mcp_observed", "merge-step", 1, 1, "", "h"); err != nil {
		t.Fatal(err)
	}
	item := journal.BlockReceipt{RunID: "run_mcp_observed", StepName: "merge-step", Seq: 1, Attempt: 1,
		CallOrdinal: 1, BlockID: "join", Kind: "merge", Mode: "full_join", LeftRows: 2,
		RightRows: 3, OutputRows: 4, MaxRows: 10, Outcome: "succeeded"}
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); err != nil {
		t.Fatal(err)
	}
	item.CallOrdinal = 2
	item.Mode = "inner_join"
	item.OutputRows = 0
	item.Outcome = "bounded_failure"
	if err := j.AppendBlockReceipt(ctx, "acme", "", item); err != nil {
		t.Fatal(err)
	}
	first := callOperationalTool(t, s, "reactor_list_run_block_receipts", map[string]any{"run_id": item.RunID, "limit": 1}, false)
	if strings.Contains(string(first), secret) || strings.Contains(string(first), "customer_id") || strings.Contains(string(first), "private-") {
		t.Fatalf("receipt read exposed customer data or join key: %s", first)
	}
	var page struct {
		Receipts []journal.BlockReceipt `json:"receipts"`
		Declared []struct {
			BlockID string `json:"block_id"`
			Status  string `json:"observation_status"`
		} `json:"declared_blocks"`
		HasMore          bool   `json:"has_more"`
		NextOffset       int    `json:"next_offset"`
		Provenance       string `json:"receipt_provenance"`
		BehaviorVerified bool   `json:"behavior_verified"`
	}
	if err := json.Unmarshal(first, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 1 || page.Receipts[0].CallOrdinal != 2 ||
		!page.HasMore || page.NextOffset != 1 || page.Provenance != "sdk_reported" || page.BehaviorVerified {
		t.Fatalf("first page = %+v", page)
	}
	statuses := map[string]string{}
	for _, declared := range page.Declared {
		statuses[declared.BlockID] = declared.Status
	}
	if statuses["join"] != "sdk_reported_shape_mismatch" || statuses["other"] != "no_sdk_observation" ||
		statuses["append"] != "observation_unsupported" || statuses["split"] != "no_sdk_observation" ||
		statuses["iterate"] != "no_sdk_observation" || statuses["aggregate"] != "no_sdk_observation" {
		t.Fatalf("declaration statuses = %+v", statuses)
	}
	second := callOperationalTool(t, s, "reactor_list_run_block_receipts", map[string]any{"run_id": item.RunID, "limit": 1, "offset": page.NextOffset}, false)
	if err := json.Unmarshal(second, &page); err != nil || len(page.Receipts) != 1 || page.Receipts[0].CallOrdinal != 1 || page.HasMore {
		t.Fatalf("second page = %+v, %v", page, err)
	}
	statuses = map[string]string{}
	for _, declared := range page.Declared {
		statuses[declared.BlockID] = declared.Status
	}
	if statuses["join"] != "sdk_reported_observation" {
		t.Fatalf("matching historical report was not distinguished from the mismatched newest report: %+v", statuses)
	}
	input, yes, no := 3, 1, 2
	split := journal.BlockReceipt{RunID: item.RunID, StepName: item.StepName, Seq: 1, Attempt: 1,
		CallOrdinal: 3, BlockID: "split", Kind: "split", InputRows: &input,
		YesRows: &yes, NoRows: &no, Outcome: "succeeded"}
	if err := j.AppendBlockReceipt(ctx, "acme", "", split); err != nil {
		t.Fatal(err)
	}
	splitPage := callOperationalTool(t, s, "reactor_list_run_block_receipts", map[string]any{"run_id": item.RunID, "limit": 1}, false)
	if strings.Contains(string(splitPage), secret) || strings.Contains(string(splitPage), "customer_id") {
		t.Fatalf("split receipt exposed customer values: %s", splitPage)
	}
	var rawSplit struct {
		Receipts []map[string]any `json:"receipts"`
	}
	if err := json.Unmarshal(splitPage, &rawSplit); err != nil || len(rawSplit.Receipts) != 1 ||
		rawSplit.Receipts[0]["left_rows"] != nil || rawSplit.Receipts[0]["max_rows"] != nil {
		t.Fatalf("split receipt exposed join-only fields: %+v, %v", rawSplit, err)
	}
	if err := json.Unmarshal(splitPage, &page); err != nil || len(page.Receipts) != 1 ||
		page.Receipts[0].Kind != "split" || page.Receipts[0].InputRows == nil || *page.Receipts[0].InputRows != 3 {
		t.Fatalf("split receipt page = %+v, %v", page, err)
	}
	statuses = map[string]string{}
	for _, declared := range page.Declared {
		statuses[declared.BlockID] = declared.Status
	}
	if statuses["split"] != "sdk_reported_observation" || statuses["iterate"] != "no_sdk_observation" {
		t.Fatalf("split status = %+v", statuses)
	}
	collectionInput := 2
	iterate := journal.BlockReceipt{RunID: item.RunID, StepName: item.StepName, Seq: 1, Attempt: 1,
		CallOrdinal: 4, BlockID: "iterate", Kind: "iterate", InputRows: &collectionInput,
		OutputRows: 2, Outcome: "succeeded"}
	if err := j.AppendBlockReceipt(ctx, "acme", "", iterate); err != nil {
		t.Fatal(err)
	}
	aggregate := iterate
	aggregate.CallOrdinal, aggregate.BlockID, aggregate.Kind, aggregate.OutputRows = 5, "aggregate", "aggregate", 1
	if err := j.AppendBlockReceipt(ctx, "acme", "", aggregate); err != nil {
		t.Fatal(err)
	}
	collectionPage := callOperationalTool(t, s, "reactor_list_run_block_receipts", map[string]any{"run_id": item.RunID, "limit": 2}, false)
	if strings.Contains(string(collectionPage), secret) || strings.Contains(string(collectionPage), "customer_id") {
		t.Fatalf("collection receipt exposed customer values: %s", collectionPage)
	}
	var rawCollection struct {
		Receipts []map[string]any `json:"receipts"`
	}
	if err := json.Unmarshal(collectionPage, &rawCollection); err != nil || len(rawCollection.Receipts) != 2 ||
		rawCollection.Receipts[0]["kind"] != "aggregate" || rawCollection.Receipts[0]["output_rows"] != float64(1) ||
		rawCollection.Receipts[1]["kind"] != "iterate" || rawCollection.Receipts[1]["output_rows"] != float64(2) {
		t.Fatalf("collection projection = %+v, %v", rawCollection, err)
	}
	for _, receipt := range rawCollection.Receipts {
		if receipt["left_rows"] != nil || receipt["yes_rows"] != nil || receipt["max_rows"] != nil || receipt["input_rows"] != float64(2) {
			t.Fatalf("collection receipt exposed unrelated fields: %+v", receipt)
		}
	}
	if err := json.Unmarshal(collectionPage, &page); err != nil {
		t.Fatal(err)
	}
	statuses = map[string]string{}
	for _, declared := range page.Declared {
		statuses[declared.BlockID] = declared.Status
	}
	if statuses["iterate"] != "sdk_reported_observation" || statuses["aggregate"] != "sdk_reported_observation" || statuses["split"] != "sdk_reported_identity_only" {
		t.Fatalf("collection declaration status = %+v", statuses)
	}
	callOperationalTool(t, s, "reactor_list_run_block_receipts", map[string]any{"run_id": item.RunID, "limit": 101}, true)
	s.TenantID = "globex"
	foreign := callOperationalTool(t, s, "reactor_list_run_block_receipts", map[string]any{"run_id": item.RunID}, true)
	if strings.Contains(string(foreign), secret) || strings.Contains(string(foreign), "join") {
		t.Fatalf("foreign tenant learned receipt details: %s", foreign)
	}
}
