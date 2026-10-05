package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReadStepOutputPage(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "large", 1, 1, "k", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "large", 1, 1, json.RawMessage(`"abcdef"`), ""); err != nil {
		t.Fatal(err)
	}

	step, chars, err := j.ReadStepOutputPage(ctx, "run_1", "large", 1, 1, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if chars != 8 || string(step.OutputJSONB) != `bcd` {
		t.Fatalf("page chars=%d output=%s", chars, step.OutputJSONB)
	}
}

func TestLatestSuccessfulStepOutputBounded(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "first", 1, 1, "k1", "h1"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "first", 1, 1, json.RawMessage(`{"value":1}`), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "hash-create-and-send", 2, 1, "k2", "h2"); err != nil {
		t.Fatal(err)
	}
	large := json.RawMessage(`"` + strings.Repeat("secret-", 100) + `"`)
	if err := j.RecordStepEndSeq(ctx, "run_1", "hash-create-and-send", 2, 1, large, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "last", 3, 1, "k3", "h3"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "last", 3, 1, json.RawMessage(`{"value":3}`), ""); err != nil {
		t.Fatal(err)
	}

	step, err := j.LatestSuccessfulStepOutputBounded(ctx, "run_1", "hash-create-and-send", 32)
	if err != nil {
		t.Fatal(err)
	}
	if step.StepName != "hash-create-and-send" || len(step.OutputJSONB) != 0 || !step.OutputTruncated || step.OutputBytes != len(large) {
		t.Fatalf("bounded named output = %+v", step)
	}
	step, err = j.LatestSuccessfulStepOutputBounded(ctx, "run_1", "", 32)
	if err != nil {
		t.Fatal(err)
	}
	if step.StepName != "last" || string(step.OutputJSONB) != `{"value":3}` || step.OutputTruncated {
		t.Fatalf("latest output = %+v", step)
	}
	if _, err := j.LatestSuccessfulStepOutputBounded(ctx, "run_1", "missing", 32); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing named output error = %v, want ErrNotFound", err)
	}
}

func TestTenantScopedRunReadsFenceForeignParent(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "private", 1, 1, "k", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "private", 1, 1, json.RawMessage(`{"secret":"step"}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := j.SaveRunLogs(ctx, "run_1", []string{"secret log"}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ScheduleSleep(ctx, "run_1", "wait", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	steps, err := j.ListStepsPageForTenant(ctx, "run_1", "foreign", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 0 {
		t.Fatalf("foreign tenant received %d step rows", len(steps))
	}
	if _, _, err := j.ReadStepOutputPageForTenant(ctx, "run_1", "foreign", "private", 1, 1, 0, 64); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign output read error = %v, want ErrNotFound", err)
	}
	logs, err := j.GetRunLogsPageForTenant(ctx, "run_1", "foreign", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 0 {
		t.Fatalf("foreign tenant received %d log lines", len(logs))
	}
	schedules, err := j.ListPendingSchedulesForRunTenant(ctx, "run_1", "foreign")
	if err != nil {
		t.Fatal(err)
	}
	if len(schedules) != 0 {
		t.Fatalf("foreign tenant received %d schedules", len(schedules))
	}
	for i := 0; i < 3; i++ {
		if _, err := j.ScheduleSleep(ctx, "run_1", "page-wait", time.Now().UTC().Add(time.Hour+time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	page, hasMore, err := j.ListPendingSchedulesForRunTenantPage(ctx, "run_1", "", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || !hasMore {
		t.Fatalf("schedule page = %d rows, hasMore=%v; want 2/true", len(page), hasMore)
	}
	foreignPage, foreignMore, err := j.ListPendingSchedulesForRunTenantPage(ctx, "run_1", "foreign", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(foreignPage) != 0 || foreignMore {
		t.Fatalf("foreign schedule page = %d rows, hasMore=%v; want 0/false", len(foreignPage), foreignMore)
	}
}

func TestBoundedRunProjectionsDoNotMaterializeLargeValues(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	largeOutput := json.RawMessage(`"` + strings.Repeat("output-secret-", 128) + `"`)
	largeError := strings.Repeat("error-secret-", 4000)
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "bounded", 1, 1, "k", "h"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEndSeq(ctx, "run_1", "bounded", 1, 1, largeOutput, largeError); err != nil {
		t.Fatal(err)
	}
	stepPage, outputChars, err := j.ReadStepOutputPage(ctx, "run_1", "bounded", 1, 1, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if outputChars != len(largeOutput) || len(stepPage.OutputJSONB) != 32 || stepPage.ErrorText != "" || stepPage.ErrorBytes != len(largeError) || !stepPage.ErrorTruncated {
		t.Fatalf("bounded step output page = chars %d, row %+v", outputChars, stepPage)
	}
	steps, err := j.ListStepsPageForTenantBounded(ctx, "run_1", "", 10, 0, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || len(steps[0].OutputJSONB) != 0 || steps[0].OutputBytes != len(largeOutput) || !steps[0].OutputTruncated || steps[0].ErrorText != "" || steps[0].ErrorBytes != len(largeError) || !steps[0].ErrorTruncated {
		t.Fatalf("bounded step projection = %+v", steps)
	}

	largeLog := strings.Repeat("log-secret-", 128)
	if err := j.SaveRunLogs(ctx, "run_1", []string{largeLog}); err != nil {
		t.Fatal(err)
	}
	logs, err := j.GetRunLogsPageForTenantBounded(ctx, "run_1", "", 10, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Text != "" || logs[0].Bytes != len(largeLog) || !logs[0].Truncated {
		t.Fatalf("bounded log projection = %+v", logs)
	}

	if _, err := j.ScheduleSignal(ctx, "run_1", "approval", "approval", "signal-secret", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.FireSignal(ctx, "signal-secret", []byte(`{"secret":"`+strings.Repeat("x", 1024)+`"}`)); err != nil {
		t.Fatal(err)
	}
	schedules, more, err := j.ListPendingSchedulesForRunTenantPageMetadata(ctx, "run_1", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(schedules) != 1 || more || schedules[0].SignalToken != "" || len(schedules[0].SignalPayload) != 0 || !schedules[0].SignalTokenPresent || !schedules[0].SignalPayloadPresent {
		t.Fatalf("metadata schedule projection = %+v, more=%v", schedules, more)
	}
}

func TestLatestBoundedStepPageReturnsNewestRowsChronologically(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for i, name := range []string{"first", "second", "third"} {
		if _, err := j.RecordStepStartSeq(ctx, "run_1", name, int64(i+1), 1, "k", "h"); err != nil {
			t.Fatal(err)
		}
		if err := j.RecordStepEndSeq(ctx, "run_1", name, int64(i+1), 1, json.RawMessage(`{"value":1}`), ""); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := j.ListLatestStepsPageForTenantBounded(ctx, "run_1", "", 2, 0, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].StepName != "second" || rows[1].StepName != "third" {
		t.Fatalf("latest bounded rows = %+v; want second, third chronological", rows)
	}
}
