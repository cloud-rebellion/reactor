package flare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	reactor "github.com/bright-interaction/reactor/sdk"
)

const (
	testNotice = `{"schema":"flare.automation.v1","event":"new_issue","project_id":"project-1","issue_id":"issue-1","event_count":3,"observed_at":"2026-10-05T10:20:30Z"}`
	testDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func testClient(t *testing.T, trip roundTripFunc) *Client {
	t.Helper()
	client, err := NewClient("https://flare.example", "project-1", "flb_test_token", &http.Client{Transport: trip})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func parsedNotice(t *testing.T) Notice {
	t.Helper()
	n, err := DecodeNotice([]byte(testNotice), "project-1")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

var testDraftConfig = DraftConfig{BaseURL: "https://flare.example", ProjectID: "project-1"}

func fixedClient(client *Client) ClientFactory {
	return func(context.Context) (*Client, error) { return client, nil }
}

func TestDecodeNoticeRejectsUnboundAndExtendedInputs(t *testing.T) {
	tests := []string{
		strings.Replace(testNotice, `"project-1"`, `"project-2"`, 1),
		strings.Replace(testNotice, `"schema":`, `"stack":"Bearer should-not-pass","schema":`, 1),
		strings.Replace(testNotice, `"schema":`, `"schema":"flare.automation.v1","schema":`, 1),
		strings.Replace(testNotice, `"schema":`, `"\u0073chema":"flare.automation.v1","schema":`, 1),
		strings.Replace(testNotice, `"event":"new_issue"`, `"event":"execute"`, 1),
		strings.Replace(testNotice, `"issue_id":"issue-1"`, `"issue_id":"../other"`, 1),
		testNotice + strings.Repeat(" ", maxNoticeBytes),
	}
	for index, raw := range tests {
		if _, err := DecodeNotice([]byte(raw), "project-1"); !errors.Is(err, ErrInvalidNotice) {
			t.Errorf("case %d accepted invalid notice: %v", index, err)
		}
	}
}

func TestNoticeDeliveryKeyIgnoresJSONLayoutButBindsIssueAndProject(t *testing.T) {
	first := parsedNotice(t)
	reformatted := `{"issue_id":"issue-1","event_count":3,"schema":"flare.automation.v1","observed_at":"2026-10-05T10:20:30Z","project_id":"project-1","event":"new_issue"}`
	second, err := DecodeNotice([]byte(reformatted), "project-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.DeliveryKey() != second.DeliveryKey() {
		t.Fatal("equivalent notices have different replay keys")
	}
	second.IssueID = "issue-2"
	if first.DeliveryKey() == second.DeliveryKey() {
		t.Fatal("different issues share a replay key")
	}
	second = first
	second.ProjectID = "project-2"
	if first.DeliveryKey() == second.DeliveryKey() {
		t.Fatal("different projects share a replay key")
	}
}

func TestUntrustedOriginAndRedirectCannotReceiveMemberCredential(t *testing.T) {
	for _, raw := range []string{"http://flare.example", "https://flare.example@evil.example", "https://flare.example/path", "https://flare.example?", "https://flare.example:8443", "https://flare.example/#fragment"} {
		if _, err := NewClient(raw, "project-1", "member-key", nil); err == nil {
			t.Fatalf("untrusted origin accepted: %s", raw)
		}
	}
	var calls int
	client := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		response := jsonResponse(http.StatusFound, "")
		response.Header.Set("Location", "https://other.example/steal")
		return response, nil
	})
	if _, err := client.TriageFresh(context.Background(), "issue-1"); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls != 1 {
		t.Fatalf("redirect followed to another origin: calls=%d", calls)
	}
}

func TestProjectMismatchStopsBeforeFreshTriage(t *testing.T) {
	var calls int
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/api/issues/issue-1" || r.Method != http.MethodGet {
			t.Fatalf("cross-project incident reached %s %s", r.Method, r.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{"id":"issue-1","project_id":"project-2","title":"ignored"}`), nil
	})
	if _, err := client.TriageFresh(context.Background(), "issue-1"); !errors.Is(err, ErrIssueScope) {
		t.Fatalf("mismatch = %v, want ErrIssueScope", err)
	}
	if calls != 1 {
		t.Fatalf("requests = %d, want only issue lookup", calls)
	}
}

func TestDraftRequiresCompletedSameIssueAIReceipt(t *testing.T) {
	notice := parsedNotice(t)
	completed := `"2026-10-05T10:20:40Z"`
	tests := []struct {
		name, receipt string
		accepted      bool
	}{
		{"wrong issue", `{"id":"ai-1","issue_id":"issue-2","operation":"triage","status":"succeeded","evidence_digest":"` + testDigest + `","completed_at":` + completed + `}`, false},
		{"wrong digest", `{"id":"ai-1","issue_id":"issue-1","operation":"triage","status":"succeeded","evidence_digest":"` + strings.Repeat("b", 64) + `","completed_at":` + completed + `}`, false},
		{"cached", `{"id":"ai-1","issue_id":"issue-1","operation":"triage","status":"cached","evidence_digest":"` + testDigest + `","completed_at":` + completed + `}`, false},
		{"not complete", `{"id":"ai-1","issue_id":"issue-1","operation":"triage","status":"succeeded","evidence_digest":"` + testDigest + `"}`, false},
		{"success", `{"id":"ai-1","issue_id":"issue-1","operation":"triage","status":"succeeded","evidence_digest":"` + testDigest + `","completed_at":` + completed + `}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer flb_test_token" {
					t.Fatal("missing scoped credential")
				}
				switch r.URL.Path {
				case "/api/issues/issue-1":
					return jsonResponse(200, `{"id":"issue-1","project_id":"project-1","title":"Bearer secret-would-be-untrusted"}`), nil
				case "/api/projects/project-1/ai-receipts/ai-1":
					return jsonResponse(200, tc.receipt), nil
				default:
					t.Fatalf("unexpected %s", r.URL.String())
					return nil, nil
				}
			})
			draft, err := client.ConfirmDraft(context.Background(), notice, FreshTriage{EvidenceDigest: testDigest, AIReceiptID: "ai-1"})
			if !tc.accepted {
				if !errors.Is(err, ErrReceiptMismatch) {
					t.Fatalf("receipt = %v, want exact evidence refusal", err)
				}
				return
			}
			if err != nil || draft.Status != "draft" || draft.AIReceiptID != "ai-1" || draft.EvidenceDigest != testDigest {
				t.Fatalf("draft = %+v, %v", draft, err)
			}
		})
	}
}

func TestExactReceiptReadRemainsPendingWithoutRepeatingTriage(t *testing.T) {
	var freshComplete bool
	var triageCalls int
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/issues/issue-1":
			return jsonResponse(200, `{"id":"issue-1","project_id":"project-1"}`), nil
		case "/api/issues/issue-1/triage":
			triageCalls++
			return jsonResponse(200, `{"cached":false,"evidence_digest":"`+testDigest+`","ai_receipt_id":"ai-new"}`), nil
		case "/api/projects/project-1/ai-receipts/ai-new":
			current := `{"id":"ai-new","issue_id":"issue-1","operation":"triage","status":"started","evidence_digest":"` + testDigest + `"}`
			if freshComplete {
				current = `{"id":"ai-new","issue_id":"issue-1","operation":"triage","status":"succeeded","evidence_digest":"` + testDigest + `","completed_at":"2026-10-05T10:20:50Z"}`
			}
			return jsonResponse(200, current), nil
		default:
			t.Fatalf("unexpected route %s", r.URL.String())
			return nil, nil
		}
	})
	flow := reactor.NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
	flow.SetSleep(func(time.Duration) {})
	if _, err := PrepareDraft(context.Background(), flow, testDraftConfig, parsedNotice(t), fixedClient(client)); !errors.Is(err, ErrReceiptPending) {
		t.Fatalf("pending exact receipt produced a draft: %v", err)
	}
	if triageCalls != 1 {
		t.Fatalf("pending receipt caused repeated AI calls: %d", triageCalls)
	}
	freshComplete = true
	draft, err := PrepareDraft(context.Background(), flow, testDraftConfig, parsedNotice(t), fixedClient(client))
	if err != nil || draft.AIReceiptID != "ai-new" || triageCalls != 1 {
		t.Fatalf("completed fresh receipt not accepted: %+v, %v", draft, err)
	}
}

func TestPrepareDraftReplaysCompletedStepsAndStoresNoTelemetry(t *testing.T) {
	var triageCalls, receiptCalls int
	secret := "Bearer abcdefghijklmnopqrstuvwxyz123456"
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/issues/issue-1":
			return jsonResponse(200, `{"id":"issue-1","project_id":"project-1","title":"`+secret+`","culprit":"private customer"}`), nil
		case "/api/issues/issue-1/triage":
			triageCalls++
			if r.Method != http.MethodPost || r.URL.Query().Get("refresh") != "true" {
				t.Fatal("fresh triage contract changed")
			}
			return jsonResponse(200, `{"cached":false,"evidence_digest":"`+testDigest+`","ai_receipt_id":"ai-1","triage":"`+secret+`"}`), nil
		case "/api/projects/project-1/ai-receipts/ai-1":
			receiptCalls++
			return jsonResponse(200, `{"id":"ai-1","issue_id":"issue-1","operation":"triage","status":"succeeded","evidence_digest":"`+testDigest+`","completed_at":"2026-10-05T10:20:40Z"}`), nil
		default:
			t.Fatalf("unexpected Flare route %s", r.URL.String())
			return nil, nil
		}
	})
	flow := reactor.NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
	notice := parsedNotice(t)
	factoryCalls := 0
	factory := func(context.Context) (*Client, error) { factoryCalls++; return client, nil }
	first, err := PrepareDraft(context.Background(), flow, testDraftConfig, notice, factory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareDraft(context.Background(), flow, testDraftConfig, notice, factory)
	if err != nil || first != second || triageCalls != 1 || receiptCalls != 1 || factoryCalls != 2 {
		t.Fatalf("replay draft=%+v err=%v triage=%d receipts=%d", second, err, triageCalls, receiptCalls)
	}
	steps := flow.Steps()
	if len(steps) != 2 {
		t.Fatalf("steps = %d, want two journaled steps", len(steps))
	}
	if fresh, ok := steps[0].Output.(FreshTriage); !ok || fresh.AIReceiptID != "ai-1" || fresh.EvidenceDigest != testDigest {
		t.Fatalf("first step did not retain exact fresh receipt and digest: %#v", steps[0].Output)
	}
	encoded, err := json.Marshal(steps)
	if err != nil || len(encoded) > 2000 || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "private customer") {
		t.Fatalf("journal projection leaked or grew: size=%d err=%v", len(encoded), err)
	}
	draftJSON, _ := json.Marshal(first)
	if len(draftJSON) > 512 || strings.Contains(string(draftJSON), secret) || !strings.Contains(string(draftJSON), `"status":"draft"`) {
		t.Fatalf("unsafe draft projection: %s", draftJSON)
	}
}

func TestLargeAndFailedFlareResponsesDoNotEchoBody(t *testing.T) {
	secret := "Bearer abcdefghijklmnopqrstuvwxyz123456"
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"oversized", 200, `{"id":"issue-1","project_id":"project-1","title":"` + strings.Repeat("x", maxIssueBytes) + `"}`, ErrResponseTooLarge},
		{"upstream error", 502, secret, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(*http.Request) (*http.Response, error) { return jsonResponse(tc.status, tc.body), nil })
			_, err := client.TriageFresh(context.Background(), "issue-1")
			if err == nil || strings.Contains(err.Error(), secret) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("unsafe error = %v", err)
			}
		})
	}
}

func TestCachedOrMissingReceiptIDCannotCreateDraft(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"cached", `{"cached":true,"evidence_digest":"` + testDigest + `","ai_receipt_id":"ai-1"}`},
		{"missing cache assertion", `{"evidence_digest":"` + testDigest + `","ai_receipt_id":"ai-1"}`},
		{"missing digest", `{"cached":false,"ai_receipt_id":"ai-1"}`},
		{"missing ID", `{"cached":false,"evidence_digest":"` + testDigest + `"}`},
		{"unsafe ID", `{"cached":false,"evidence_digest":"` + testDigest + `","ai_receipt_id":"../other"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodGet {
					return jsonResponse(200, `{"id":"issue-1","project_id":"project-1"}`), nil
				}
				return jsonResponse(200, tc.body), nil
			})
			if _, err := client.TriageFresh(context.Background(), "issue-1"); !errors.Is(err, ErrFreshTriage) {
				t.Fatalf("triage = %v, want fresh triage error", err)
			}
		})
	}
}
