package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const mailTestDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func admitMailSendTest(j *Journal, ctx context.Context, runID, leaseOwner, stepName string, seq int64, attempt int, idempotencyKey, requestDigest string) (MailSendAdmission, error) {
	return j.AdmitMailSend(ctx, runID, leaseOwner, stepName, seq, attempt, idempotencyKey, requestDigest,
		MailSendTarget{ProviderID: "google", ConnectionID: "conn_test"})
}

func admitMailSendMicrosoftTest(j *Journal, ctx context.Context, runID, leaseOwner, stepName string, seq int64, attempt int, idempotencyKey, requestDigest string) (MailSendAdmission, error) {
	return j.AdmitMailSend(ctx, runID, leaseOwner, stepName, seq, attempt, idempotencyKey, requestDigest,
		MailSendTarget{ProviderID: "microsoft", ConnectionID: "conn_test"})
}

func TestMailSendIntentLocalAdmissionReplayAndConfirmation(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := admitMailSendTest(j, ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest); !errors.Is(err, ErrStepAttemptNotRunning) {
		t.Fatalf("no step: %v", err)
	}
	claim, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "key", "input")
	if err != nil || claim.Attempt != 1 {
		t.Fatalf("step claim = %+v, %v", claim, err)
	}
	for _, tc := range []struct {
		name, step, key, digest string
		seq, attempt            int64
	}{
		{"wrong key", "send", "other", mailTestDigest, 1, 1},
		{"wrong step", "other", "key", mailTestDigest, 1, 1},
		{"wrong attempt", "send", "key", mailTestDigest, 1, 2},
		{"legacy ordinal", "send", "key", mailTestDigest, 0, 1},
		{"bad digest", "send", "key", "x", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if admission, err := admitMailSendTest(j, ctx, "run_1", "", tc.step, tc.seq, int(tc.attempt), tc.key, tc.digest); err == nil {
				t.Fatalf("admitted invalid call: %+v", admission)
			}
		})
	}
	if _, err := j.AdmitMailSend(ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest, MailSendTarget{}); err == nil {
		t.Fatal("mail intent admitted without a provider and connection target")
	}
	first, err := admitMailSendTest(j, ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest)
	if err != nil || first.Disposition != MailSendDispositionSend || first.IntentID == "" {
		t.Fatalf("first admission = %+v, %v", first, err)
	}
	if err := j.ConfirmMailSend(ctx, first.IntentID, "microsoft", "wrong-provider"); err == nil {
		t.Fatal("different provider confirmed a google intent")
	}
	replay, err := admitMailSendTest(j, ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest)
	if err != nil || replay.Disposition != MailSendDispositionAmbiguous || replay.IntentID != first.IntentID {
		t.Fatalf("unconfirmed replay = %+v, %v", replay, err)
	}
	if err := j.ConfirmMailSend(ctx, first.IntentID, "google", "provider-message-1"); err != nil {
		t.Fatal(err)
	}
	if err := j.ConfirmMailSend(ctx, first.IntentID, "google", "provider-message-1"); err != nil {
		t.Fatalf("exact confirmation replay: %v", err)
	}
	if err := j.ConfirmMailSend(ctx, first.IntentID, "google", "different-id"); err == nil {
		t.Fatal("conflicting provider acceptance overwritten")
	}
	replay, err = admitMailSendTest(j, ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest)
	if err != nil || replay.Disposition != MailSendDispositionConfirmed || replay.IntentID != first.IntentID ||
		replay.ProviderID != "google" || replay.MessageID != "provider-message-1" {
		t.Fatalf("confirmed replay = %+v, %v", replay, err)
	}
	replay, err = j.AdmitMailSend(ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest,
		MailSendTarget{ProviderID: "google", ConnectionID: "conn_other"})
	if err != nil || replay.Disposition != MailSendDispositionAmbiguous {
		t.Fatalf("different target connection replay = %+v, %v", replay, err)
	}
	changedDigest := strings.Repeat("a", 64)
	replay, err = admitMailSendTest(j, ctx, "run_1", "", "send", 1, 1, "key", changedDigest)
	if err != nil || replay.Disposition != MailSendDispositionAmbiguous {
		t.Fatalf("changed request replay = %+v, %v", replay, err)
	}

	if _, err := j.FinalizeStepAttemptSeqWithRetryAfter(ctx, "run_1", "send", 1, 1, json.RawMessage(`null`), "retry", true, 0); err != nil {
		t.Fatal(err)
	}
	claim, err = j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "key", "input")
	if err != nil || claim.Attempt != 2 {
		t.Fatalf("second step claim = %+v, %v", claim, err)
	}
	replay, err = admitMailSendTest(j, ctx, "run_1", "", "send", 1, 2, "key", mailTestDigest)
	if err != nil || replay.Disposition != MailSendDispositionConfirmed || replay.MessageID != "provider-message-1" {
		t.Fatalf("confirmed step retry = %+v, %v", replay, err)
	}
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_1", "different-step", 1, 1, "other-key", "other-input"); err != nil {
		t.Fatal(err)
	}
	replay, err = admitMailSendTest(j, ctx, "run_1", "", "different-step", 1, 1, "other-key", mailTestDigest)
	if err != nil || replay.Disposition != MailSendDispositionAmbiguous {
		t.Fatalf("same ordinal under different step = %+v, %v", replay, err)
	}
	if _, err := admitMailSendTest(j, ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest); !errors.Is(err, ErrStepAttemptNotRunning) {
		t.Fatalf("stale step attempt: %v", err)
	}
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if _, err := admitMailSendTest(j, ctx, "run_1", "", "send", 1, 2, "key", mailTestDigest); !errors.Is(err, ErrLeaseOwnershipLost) {
		t.Fatalf("finished run admission: %v", err)
	}
}

func TestMailSendIntentRunAndLeaseFences(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		t.Run(engine, func(t *testing.T) {
			var j *Journal
			var cleanup func()
			if engine == "postgres" {
				j, cleanup = newOwnedStepPostgresJournal(t)
			} else {
				j, cleanup = newTestJournal(t)
			}
			defer cleanup()
			ctx := context.Background()
			if engine == "postgres" {
				if err := j.CreateWorkflow(ctx, "wf_1", "mail", "hash", "0.1.0", json.RawMessage(`{}`)); err != nil {
					t.Fatal(err)
				}
			}
			if err := j.CreateQueuedRun(ctx, "run_mail_lease", "wf_1", "manual", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			claims, err := j.ClaimQueuedRuns(ctx, "worker-mail-a", 1, time.Minute)
			if err != nil || len(claims) != 1 || claims[0].RunID != "run_mail_lease" {
				t.Fatalf("first lease = %+v, %v", claims, err)
			}
			owner := claims[0].Owner
			if _, err := j.ClaimOwnedStepAttemptSeq(ctx, "run_mail_lease", owner, "send", 1, 3, "key", "input"); err != nil {
				t.Fatal(err)
			}
			for _, badOwner := range []string{"", "wrong-owner"} {
				if admission, err := admitMailSendMicrosoftTest(j, ctx, "run_mail_lease", badOwner, "send", 1, 1, "key", mailTestDigest); !errors.Is(err, ErrLeaseOwnershipLost) {
					t.Fatalf("owner %q admission = %+v, %v", badOwner, admission, err)
				}
			}
			first, err := admitMailSendMicrosoftTest(j, ctx, "run_mail_lease", owner, "send", 1, 1, "key", mailTestDigest)
			if err != nil || first.Disposition != MailSendDispositionSend {
				t.Fatalf("owned admission = %+v, %v", first, err)
			}
			if err := j.ExtendLease(ctx, "run_mail_lease", owner, -time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := admitMailSendMicrosoftTest(j, ctx, "run_mail_lease", owner, "send", 1, 1, "key", mailTestDigest); !errors.Is(err, ErrLeaseOwnershipLost) {
				t.Fatalf("expired lease admission: %v", err)
			}
			// Provider acceptance may already have happened before expiry.
			if err := j.ConfirmMailSend(ctx, first.IntentID, "microsoft", ""); err != nil {
				t.Fatalf("post-expiry provider confirmation: %v", err)
			}
			if n, err := j.ReapExpiredLeases(ctx); err != nil || n != 1 {
				t.Fatalf("reap = %d, %v", n, err)
			}
			claims, err = j.ClaimQueuedRuns(ctx, "worker-mail-b", 1, time.Minute)
			if err != nil || len(claims) != 1 || claims[0].RunID != "run_mail_lease" {
				t.Fatalf("replacement lease = %+v, %v", claims, err)
			}
			if _, err := j.ClaimOwnedStepAttemptSeq(ctx, "run_mail_lease", claims[0].Owner, "send", 1, 3, "key", "input"); err != nil {
				t.Fatal(err)
			}
			replay, err := admitMailSendMicrosoftTest(j, ctx, "run_mail_lease", claims[0].Owner, "send", 1, 2, "key", mailTestDigest)
			if err != nil || replay.Disposition != MailSendDispositionConfirmed || replay.ProviderID != "microsoft" || replay.MessageID != "" {
				t.Fatalf("replacement replay = %+v, %v", replay, err)
			}
			if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE runs SET cancel_requested = $1 WHERE id = $2`), j.boolValue(true), "run_mail_lease"); err != nil {
				t.Fatal(err)
			}
			if _, err := admitMailSendMicrosoftTest(j, ctx, "run_mail_lease", claims[0].Owner, "send", 1, 2, "key", mailTestDigest); !errors.Is(err, ErrLeaseOwnershipLost) {
				t.Fatalf("cancelled run admission: %v", err)
			}
		})
	}
}

func TestMailSendIntentConcurrentAdmissionHasOneSend(t *testing.T) {
	j, cleanup := newTestJournal(t)
	defer cleanup()
	// One SQLite connection serializes the two admission transactions while
	// still proving only one caller receives the durable send disposition.
	j.db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := j.ClaimStepAttemptSeq(ctx, "run_1", "send", 1, 3, "key", "input"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan MailSendAdmission, 8)
	errorsCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := admitMailSendTest(j, ctx, "run_1", "", "send", 1, 1, "key", mailTestDigest)
			results <- result
			errorsCh <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	sends, ambiguous := 0, 0
	for result := range results {
		switch result.Disposition {
		case MailSendDispositionSend:
			sends++
		case MailSendDispositionAmbiguous:
			ambiguous++
		default:
			t.Fatalf("unexpected disposition: %+v", result)
		}
	}
	if sends != 1 || ambiguous != 7 {
		t.Fatalf("concurrent admissions: send=%d ambiguous=%d", sends, ambiguous)
	}
}
