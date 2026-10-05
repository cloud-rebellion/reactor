package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestMCPMailSendProjectionBoundsImportedIdentityAndProvider(t *testing.T) {
	view := mcpMailSendIntentView(journal.MailSendIntentReceipt{
		ID: strings.Repeat("i", 512), StepName: strings.Repeat("å", 512),
		Status: "confirmed", ProviderID: "private-provider-token", CreatedAt: time.Now(), ConfirmedAt: time.Now(),
	})
	if len(view["intent_id"].(string)) > 128 || view["intent_id_truncated"] != true ||
		len(view["step_name"].(string)) > 256 || view["step_name_truncated"] != true ||
		view["provider_id"] != "unknown" {
		t.Fatalf("unbounded or unsafe mail intent metadata: %+v", view)
	}
}

func TestHTTPMCPMailSendReceiptsAreTenantScopedBoundedAndValueFree(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	const secret = "private-recipient-and-oauth-token"
	if err := j.CreateWorkflowInTenant(ctx, "wf_mail_read", "mail-read", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_mail_read", "wf_mail_read", "manual", json.RawMessage(`{"private":"`+secret+`"}`)); err != nil {
		t.Fatal(err)
	}
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, step := range []struct {
		name string
		seq  int64
	}{
		{"send-first", 1}, {"send-second", 2},
	} {
		if _, err := j.ClaimStepAttemptSeq(ctx, "run_mail_read", step.name, step.seq, 3, secret, "input"); err != nil {
			t.Fatal(err)
		}
		admission, err := j.AdmitMailSend(ctx, "run_mail_read", "", step.name, step.seq, 1, secret, digest,
			journal.MailSendTarget{ProviderID: "google", ConnectionID: "conn_mail_test"})
		if err != nil {
			t.Fatal(err)
		}
		if step.seq == 2 {
			if err := j.ConfirmMailSend(ctx, admission.IntentID, "google", "private-provider-message-id"); err != nil {
				t.Fatal(err)
			}
		}
	}
	first := callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_read", "limit": 1}, false)
	if strings.Contains(string(first), secret) || strings.Contains(string(first), digest) || strings.Contains(string(first), "private-provider-message-id") {
		t.Fatalf("mail send receipt leaked private values: %s", first)
	}
	var page struct {
		MailSends []struct {
			Status                    string `json:"status"`
			ProviderID                string `json:"provider_id"`
			ConnectionID              string `json:"connection_id"`
			TargetRecorded            bool   `json:"target_recorded"`
			ProviderMessageIDRecorded bool   `json:"provider_message_id_recorded"`
		} `json:"mail_sends"`
		HasMore    bool `json:"has_more"`
		NextOffset int  `json:"next_offset"`
	}
	if err := json.Unmarshal(first, &page); err != nil || len(page.MailSends) != 1 || page.MailSends[0].Status != "admitted" ||
		page.MailSends[0].ProviderID != "google" || page.MailSends[0].ConnectionID != "conn_mail_test" ||
		!page.MailSends[0].TargetRecorded || page.MailSends[0].ProviderMessageIDRecorded || !page.HasMore || page.NextOffset != 1 {
		t.Fatalf("first mail page = %+v, %v", page, err)
	}
	second := callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_read", "limit": 1, "offset": page.NextOffset}, false)
	if err := json.Unmarshal(second, &page); err != nil || len(page.MailSends) != 1 || page.MailSends[0].Status != "confirmed" ||
		page.MailSends[0].ProviderID != "google" || page.MailSends[0].ConnectionID != "conn_mail_test" ||
		!page.MailSends[0].TargetRecorded || !page.MailSends[0].ProviderMessageIDRecorded || page.HasMore {
		t.Fatalf("second mail page = %+v, %v", page, err)
	}
	if strings.Contains(string(second), "private-provider-message-id") {
		t.Fatalf("provider message ID crossed MCP boundary: %s", second)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_mail_foreign", "mail-foreign", "hash", "0.1.0", json.RawMessage(`{}`), "other"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_mail_foreign", "wf_mail_foreign", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_mail_empty", "wf_mail_read", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	var empty struct {
		MailSends []map[string]any `json:"mail_sends"`
	}
	if err := json.Unmarshal(callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_empty"}, false), &empty); err != nil || len(empty.MailSends) != 0 {
		t.Fatalf("retained run with no sends = %+v, %v", empty, err)
	}
	callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_missing"}, true)
	callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_foreign"}, true)
	callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_read", "limit": 101}, true)
	callOperationalTool(t, s, "reactor_list_run_mail_sends", map[string]any{"run_id": "run_mail_read", "offset": -1}, true)
}

func TestHTTPMCPUncertainMailInventoryAcrossRunsIsTenantScopedAndValueFree(t *testing.T) {
	s, j, _ := newTestServer(t, false)
	s.TenantID = "acme"
	ctx := context.Background()
	const secret = "private-recipient-token-and-message"
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct{ tenant, workflowID, runID string }{
		{"acme", "wf_mail_queue_acme", "run_mail_queue_a"},
		{"acme", "wf_mail_queue_acme", "run_mail_queue_b"},
		{"other", "wf_mail_queue_other", "run_mail_queue_foreign"},
	} {
		if tc.runID == "run_mail_queue_a" || tc.runID == "run_mail_queue_foreign" {
			if err := j.CreateWorkflowInTenant(ctx, tc.workflowID, "mail-queue-"+tc.tenant, "hash", "0.1.0", json.RawMessage(`{}`), tc.tenant); err != nil {
				t.Fatal(err)
			}
		}
		if err := j.CreateRun(ctx, tc.runID, tc.workflowID, "manual", json.RawMessage(`{"recipient":"`+secret+`"}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ClaimStepAttemptSeq(ctx, tc.runID, "send", 1, 3, secret, "input"); err != nil {
			t.Fatal(err)
		}
		if _, err := j.AdmitMailSend(ctx, tc.runID, "", "send", 1, 1, secret, digest,
			journal.MailSendTarget{ProviderID: "google", ConnectionID: "conn_operator"}); err != nil {
			t.Fatal(err)
		}
	}
	var ids []string
	var cursor string
	for pageNum := 0; pageNum < 2; pageNum++ {
		args := map[string]any{"limit": 1}
		if cursor != "" {
			args["cursor"] = cursor
		}
		body := callOperationalTool(t, s, "reactor_list_uncertain_mail_sends", args, false)
		if strings.Contains(string(body), secret) || strings.Contains(string(body), digest) || strings.Contains(string(body), "run_mail_queue_foreign") {
			t.Fatalf("uncertain-mail inventory leaked private data or foreign run: %s", body)
		}
		var result struct {
			MailSends []struct {
				RunID          string `json:"run_id"`
				Status         string `json:"status"`
				ProviderID     string `json:"provider_id"`
				ConnectionID   string `json:"connection_id"`
				TargetRecorded bool   `json:"target_recorded"`
			} `json:"mail_sends"`
			HasMore              bool   `json:"has_more"`
			NextCursor           string `json:"next_cursor"`
			AutomaticRedriveSafe bool   `json:"automatic_redrive_safe"`
		}
		if err := json.Unmarshal(body, &result); err != nil || len(result.MailSends) != 1 ||
			result.MailSends[0].Status != "admitted" || result.MailSends[0].ProviderID != "google" ||
			result.MailSends[0].ConnectionID != "conn_operator" || !result.MailSends[0].TargetRecorded ||
			result.HasMore != (pageNum == 0) || result.AutomaticRedriveSafe {
			t.Fatalf("uncertain-mail page %d = %+v, err=%v", pageNum, result, err)
		}
		ids = append(ids, result.MailSends[0].RunID)
		cursor = result.NextCursor
	}
	if ids[0] == ids[1] {
		t.Fatalf("cursor duplicated run: %v", ids)
	}
	callOperationalTool(t, s, "reactor_list_uncertain_mail_sends", map[string]any{"limit": 101}, true)
	callOperationalTool(t, s, "reactor_list_uncertain_mail_sends", map[string]any{"cursor": "invalid cursor"}, true)
}
