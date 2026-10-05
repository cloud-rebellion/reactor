package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestRunDetailShowsBoundedStepHistoryReceipt(t *testing.T) {
	ctx := context.Background()
	j := journalForServerTest(t)
	artifact := strings.Repeat("a", 64)
	dag := json.RawMessage(`{"steps":[{"name":"early","kind":"step"},{"name":"repeat","kind":"step"}]}`)
	if err := j.CreateWorkflowInTenantWithArtifact(ctx, "wf_many_steps", "many-steps", "h", "0.1.0", artifact, dag, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRunPinned(ctx, "run_many_steps", "wf_many_steps", "manual", json.RawMessage(`{}`), 1, artifact); err != nil {
		t.Fatal(err)
	}
	s := &Server{Journal: j}
	for seq := 1; seq <= maxRunDetailStepRows; seq++ {
		if _, err := j.RecordStepStartSeq(ctx, "run_many_steps", "repeat", int64(seq), 1, fmt.Sprintf("key-%d", seq), "h"); err != nil {
			t.Fatal(err)
		}
	}
	steps, omitted, err := s.runDetailSteps(ctx, "run_many_steps", "acme")
	if err != nil || omitted || len(steps) != maxRunDetailStepRows {
		t.Fatalf("exact-bound step window: rows=%d omitted=%v err=%v", len(steps), omitted, err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_many_steps", "repeat", maxRunDetailStepRows+1, 1, "key-extra", "h"); err != nil {
		t.Fatal(err)
	}
	steps, omitted, err = s.runDetailSteps(ctx, "run_many_steps", "acme")
	var first, last int64
	if len(steps) > 0 {
		first, last = steps[0].Seq, steps[len(steps)-1].Seq
	}
	if err != nil || !omitted || len(steps) != maxRunDetailStepRows || first != 2 || last != maxRunDetailStepRows+1 {
		t.Fatalf("overflow step window: first=%d last=%d rows=%d omitted=%v err=%v", first, last, len(steps), omitted, err)
	}
	foreign, foreignOmitted, err := s.runDetailSteps(ctx, "run_many_steps", "globex")
	if err != nil || len(foreign) != 0 || foreignOmitted {
		t.Fatalf("foreign tenant step window: rows=%d omitted=%v err=%v", len(foreign), foreignOmitted, err)
	}

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/runs/run_many_steps", nil), "id", "run_many_steps")
	rec := httptest.NewRecorder()
	s.runDetail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run detail HTTP %d: %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	for _, want := range []string{
		"Showing the most recent 1000 recorded step attempts", "bounded check found additional attempts outside this view",
		"1 not observed in displayed window", "no attempt in displayed window", "1000 attempt receipts shown",
		"<th>Call</th>", "<td>call #2</td>", "<td>call #1001</td>",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("bounded run detail missing %q", want)
		}
	}
	if strings.Contains(page, "<td>call #1</td>") {
		t.Fatal("run detail displayed an attempt outside the newest bounded window")
	}
	foreignReq := withChiParam(httptest.NewRequest(http.MethodGet, "/runs/run_many_steps", nil), "id", "run_many_steps")
	foreignReq = foreignReq.WithContext(withUser(foreignReq.Context(), auth.User{ID: "foreign", Role: auth.RoleMember, TenantID: "globex"}))
	foreignRec := httptest.NewRecorder()
	s.runDetail(foreignRec, foreignReq)
	if foreignRec.Code != http.StatusNotFound || strings.Contains(foreignRec.Body.String(), "repeat") {
		t.Fatalf("foreign tenant run detail exposed step history: status=%d body=%q", foreignRec.Code, foreignRec.Body.String())
	}
}

func TestRunDetailTimelineDistinguishesCallsFromRetries(t *testing.T) {
	t.Parallel()
	page := runDetailBody(journal.RunInfo{ID: "run_repeat"}, []journal.StepRow{
		{StepName: "repeat", Seq: 1, Attempt: 1, Status: "succeeded"},
		{StepName: "repeat", Seq: 2, Attempt: 1, Status: "failed"},
		{StepName: "repeat", Seq: 2, Attempt: 2, Status: "succeeded"},
		{StepName: "legacy", Seq: 0, Attempt: 1, Status: "succeeded"},
	}, "", "", "", nil, false)
	for _, want := range []string{
		"<th>Call</th><th>Attempt</th>", "<td>call #1</td><td>1</td>",
		"<td>call #2</td><td>1</td>", "<td>call #2</td><td>2</td>",
		"<td>legacy call (ordinal unavailable)</td>",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("step timeline missing %q: %s", want, page)
		}
	}
}
