package journal

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"
)

func TestListAdmittedMailSendsAcrossRunsTenantCursorAndConfirmation(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	const secret = "private-address-and-token"
	for _, tenant := range []string{"acme", "other"} {
		if err := j.CreateWorkflowInTenant(ctx, "wf_"+tenant, "mail-"+tenant, "hash", "0.1.0", json.RawMessage(`{}`), tenant); err != nil {
			t.Fatal(err)
		}
	}
	var acmeIDs []string
	for _, tc := range []struct{ runID, workflowID string }{
		{"run_acme_a", "wf_acme"}, {"run_acme_b", "wf_acme"},
		{"run_acme_c", "wf_acme"}, {"run_other", "wf_other"},
	} {
		if err := j.CreateRun(ctx, tc.runID, tc.workflowID, "manual", json.RawMessage(`{"private":"`+secret+`"}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ClaimStepAttemptSeq(ctx, tc.runID, "send", 1, 3, secret, "input"); err != nil {
			t.Fatal(err)
		}
		admission, err := j.AdmitMailSend(ctx, tc.runID, "", "send", 1, 1, secret, mailTestDigest,
			MailSendTarget{ProviderID: "google", ConnectionID: "conn_test"})
		if err != nil {
			t.Fatal(err)
		}
		if tc.workflowID == "wf_acme" {
			acmeIDs = append(acmeIDs, admission.IntentID)
		}
		var stampedTenant string
		if err := j.db.QueryRowContext(ctx, j.bind(`SELECT tenant_id FROM mail_send_intents WHERE id = $1`), admission.IntentID).Scan(&stampedTenant); err != nil ||
			(stampedTenant != "acme" && stampedTenant != "other") {
			t.Fatalf("admission tenant = %q, %v", stampedTenant, err)
		}
	}
	// Make the time equal to prove the opaque ID is a stable seek tie-breaker.
	tie := j.formatTime(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE mail_send_intents SET created_at = $1`), tie); err != nil {
		t.Fatal(err)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(acmeIDs)))
	var got []string
	var cursor string
	for page := 0; page < 3; page++ {
		items, more, next, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 1, cursor)
		if err != nil || len(items) != 1 || items[0].Status != "admitted" || items[0].RunID == "run_other" ||
			items[0].ProviderID != "google" || items[0].ConnectionID != "conn_test" || items[0].TargetRecorded != true ||
			more != (page < 2) {
			t.Fatalf("page %d = %+v, more=%v, next=%q, err=%v", page, items, more, next, err)
		}
		got = append(got, items[0].ID)
		cursor = next
	}
	for i := range got {
		if got[i] != acmeIDs[i] {
			t.Fatalf("cursor order = %v, want %v", got, acmeIDs)
		}
	}
	if _, _, _, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 1, "invalid cursor"); !errors.Is(err, ErrInvalidMailSendCursor) {
		t.Fatalf("malformed cursor = %v", err)
	}
	if err := j.ConfirmMailSend(ctx, acmeIDs[1], "google", "private-provider-message-id"); err != nil {
		t.Fatal(err)
	}
	first, more, next, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 1, "")
	if err != nil || !more || len(first) != 1 || first[0].ID != acmeIDs[0] {
		t.Fatalf("queue after confirmation = %+v, %v, %v", first, more, err)
	}
	second, more, _, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 1, next)
	if err != nil || more || len(second) != 1 || second[0].ID != acmeIDs[2] {
		t.Fatalf("second page after confirmation = %+v, %v, %v", second, more, err)
	}
}

func TestListMailSendIntentsForRunTenantIsBoundedAndValueFree(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, row := range []struct {
		id, step, status, provider, message string
		seq                                 int
	}{
		{"intent-a", "send-a", "admitted", "", "", 1},
		{"intent-b", "send-b", "confirmed", "gmail", "private-provider-message-id", 2},
	} {
		_, err := j.db.ExecContext(ctx, `INSERT INTO mail_send_intents
			(id, run_id, step_name, seq, attempt, idempotency_key_sha256, request_sha256,
			 status, provider_id, message_id, created_at, confirmed_at)
			 VALUES (?, 'run_1', ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)`,
			row.id, row.step, row.seq, mailTestDigest, mailTestDigest, row.status,
			nullable(row.provider), nullable(row.message), j.now(), func() any {
				if row.status == "confirmed" {
					return j.now()
				}
				return nil
			}())
		if err != nil {
			t.Fatal(err)
		}
	}
	items, more, err := j.ListMailSendIntentsForRunTenant(ctx, "run_1", DefaultTenant, 1, 0)
	if err != nil || !more || len(items) != 1 || items[0].Status != "admitted" || items[0].MessageIDKnown || items[0].TargetRecorded || items[0].ProviderID != "" {
		t.Fatalf("first page = %+v, more=%v, err=%v", items, more, err)
	}
	items, more, err = j.ListMailSendIntentsForRunTenant(ctx, "run_1", DefaultTenant, 1, 1)
	if err != nil || more || len(items) != 1 || items[0].Status != "confirmed" || !items[0].MessageIDKnown || items[0].TargetRecorded || items[0].ProviderID != "gmail" || items[0].ConfirmedAt.IsZero() {
		t.Fatalf("second page = %+v, more=%v, err=%v", items, more, err)
	}
	items, more, err = j.ListMailSendIntentsForRunTenant(ctx, "run_1", "foreign", 10, 0)
	if err != nil || more || len(items) != 0 {
		t.Fatalf("foreign tenant page = %+v, more=%v, err=%v", items, more, err)
	}
	if _, _, err := j.ListMailSendIntentsForRunTenant(ctx, "run_1", DefaultTenant, 101, 0); err == nil {
		t.Fatal("unbounded page accepted")
	}
	if _, _, err := j.ListMailSendIntentsForRunTenant(ctx, "", DefaultTenant, 1, 0); err == nil {
		t.Fatal("empty run accepted")
	}
}

func TestListMailSendIntentsForRunTenantPostgres(t *testing.T) {
	j, cleanup := newOwnedStepPostgresJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_mail_read_pg", "mail-read-pg", "hash", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_mail_read_pg", "wf_mail_read_pg", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_mail_read_pg", "send", 1, 3, "private-key", "input"); err != nil {
		t.Fatal(err)
	}
	admitted, err := j.AdmitMailSend(ctx, "run_mail_read_pg", "", "send", 1, 1, "private-key", mailTestDigest,
		MailSendTarget{ProviderID: "google", ConnectionID: "conn_mail_pg"})
	if err != nil {
		t.Fatal(err)
	}
	items, more, err := j.ListMailSendIntentsForRunTenant(ctx, "run_mail_read_pg", "acme", 1, 0)
	if err != nil || more || len(items) != 1 || items[0].ID != admitted.IntentID || items[0].Status != "admitted" ||
		!items[0].TargetRecorded || items[0].ProviderID != "google" || items[0].ConnectionID != "conn_mail_pg" || items[0].CreatedAt.IsZero() {
		t.Fatalf("PostgreSQL admitted read = %+v, more=%v, err=%v", items, more, err)
	}
	if err := j.ConfirmMailSend(ctx, admitted.IntentID, "google", "private-message-id"); err != nil {
		t.Fatal(err)
	}
	items, more, err = j.ListMailSendIntentsForRunTenant(ctx, "run_mail_read_pg", "acme", 1, 0)
	if err != nil || more || len(items) != 1 || items[0].Status != "confirmed" || items[0].ProviderID != "google" ||
		items[0].ConnectionID != "conn_mail_pg" || !items[0].MessageIDKnown || items[0].ConfirmedAt.IsZero() {
		t.Fatalf("PostgreSQL confirmed read = %+v, more=%v, err=%v", items, more, err)
	}
	items, more, err = j.ListMailSendIntentsForRunTenant(ctx, "run_mail_read_pg", "other", 1, 0)
	if err != nil || more || len(items) != 0 {
		t.Fatalf("PostgreSQL foreign read = %+v, more=%v, err=%v", items, more, err)
	}
}

func TestAdmittedMailSendTenantInventoryPostgres(t *testing.T) {
	j, cleanup := newOwnedStepPostgresJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, tc := range []struct{ tenant, workflowID, runID string }{
		{"acme", "wf_mail_queue_pg_acme", "run_mail_queue_pg_a"},
		{"acme", "wf_mail_queue_pg_acme", "run_mail_queue_pg_b"},
		{"other", "wf_mail_queue_pg_other", "run_mail_queue_pg_other"},
	} {
		if tc.runID == "run_mail_queue_pg_a" || tc.runID == "run_mail_queue_pg_other" {
			if err := j.CreateWorkflowInTenant(ctx, tc.workflowID, "mail-queue-pg-"+tc.tenant, "hash", "0.1.0", json.RawMessage(`{}`), tc.tenant); err != nil {
				t.Fatal(err)
			}
		}
		if err := j.CreateRun(ctx, tc.runID, tc.workflowID, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.ClaimStepAttemptSeq(ctx, tc.runID, "send", 1, 3, "key", "input"); err != nil {
			t.Fatal(err)
		}
		if _, err := j.AdmitMailSend(ctx, tc.runID, "", "send", 1, 1, "key", mailTestDigest,
			MailSendTarget{ProviderID: "microsoft", ConnectionID: "conn_mail_queue_pg"}); err != nil {
			t.Fatal(err)
		}
	}
	first, more, next, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 1, "")
	if err != nil || !more || len(first) != 1 || next == "" || first[0].RunID == "run_mail_queue_pg_other" {
		t.Fatalf("PostgreSQL first queue page = %+v, more=%v, next=%q, err=%v", first, more, next, err)
	}
	second, more, _, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 1, next)
	if err != nil || more || len(second) != 1 || second[0].RunID == first[0].RunID || second[0].RunID == "run_mail_queue_pg_other" {
		t.Fatalf("PostgreSQL second queue page = %+v, more=%v, err=%v", second, more, err)
	}
	foreign, more, _, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "other", 10, "")
	if err != nil || more || len(foreign) != 1 || foreign[0].RunID != "run_mail_queue_pg_other" {
		t.Fatalf("PostgreSQL other tenant = %+v, more=%v, err=%v", foreign, more, err)
	}
	if err := j.ConfirmMailSend(ctx, first[0].ID, "microsoft", ""); err != nil {
		t.Fatal(err)
	}
	remaining, more, _, err := j.ListAdmittedMailSendIntentsForTenant(ctx, "acme", 10, "")
	if err != nil || more || len(remaining) != 1 || remaining[0].ID != second[0].ID {
		t.Fatalf("PostgreSQL queue after confirmation = %+v, more=%v, err=%v", remaining, more, err)
	}
	if err := j.CreateRun(ctx, "run_mail_queue_pg_legacy_writer", "wf_mail_queue_pg_acme", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO mail_send_intents
		(id, run_id, step_name, seq, attempt, idempotency_key_sha256, request_sha256, status, created_at)
		VALUES ('intent_mail_pg_legacy_writer', 'run_mail_queue_pg_legacy_writer', 'send', 1, 1, $1, $2, 'admitted', $3)`,
		mailTestDigest, mailTestDigest, j.now()); err != nil {
		t.Fatal(err)
	}
	var stampedTenant string
	if err := j.db.QueryRowContext(ctx, `SELECT tenant_id FROM mail_send_intents WHERE id = 'intent_mail_pg_legacy_writer'`).Scan(&stampedTenant); err != nil || stampedTenant != "acme" {
		t.Fatalf("PostgreSQL legacy-writer intent tenant = %q, %v", stampedTenant, err)
	}
}
