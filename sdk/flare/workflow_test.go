package flare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	reactor "github.com/bright-interaction/reactor/sdk"
	flowruntime "github.com/bright-interaction/reactor/sdk/runtime"
	"github.com/bright-interaction/reactor/sdk/wire"
)

func successfulClient(t *testing.T, triages, receipts *int) *Client {
	t.Helper()
	return testClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/issues/issue-1":
			return jsonResponse(200, `{"id":"issue-1","project_id":"project-1"}`), nil
		case "/api/issues/issue-1/triage":
			*triages++
			return jsonResponse(200, `{"cached":false,"evidence_digest":"`+testDigest+`","ai_receipt_id":"ai-1"}`), nil
		case "/api/projects/project-1/ai-receipts/ai-1":
			*receipts++
			return jsonResponse(200, `{"id":"ai-1","issue_id":"issue-1","operation":"triage","status":"succeeded","evidence_digest":"`+testDigest+`","completed_at":"2026-10-18T10:20:40Z"}`), nil
		default:
			t.Fatalf("unexpected Flare route %s", r.URL)
			return nil, nil
		}
	})
}

func TestFailedAndForeignReceiptsAreTerminal(t *testing.T) {
	for _, tc := range []struct{ name, receipt string }{
		{"failed", `{"id":"ai-1","issue_id":"issue-1","operation":"triage","status":"failed"}`},
		{"foreign issue", `{"id":"ai-1","issue_id":"issue-2","operation":"triage","status":"succeeded"}`},
		{"wrong operation", `{"id":"ai-1","issue_id":"issue-1","operation":"fix","status":"succeeded"}`},
		{"older receipt with same digest", `{"id":"ai-old","issue_id":"issue-1","operation":"triage","status":"succeeded","evidence_digest":"` + testDigest + `","completed_at":"2026-10-18T10:20:40Z"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var triages, receipts int
			client := testClient(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/api/issues/issue-1":
					return jsonResponse(200, `{"id":"issue-1","project_id":"project-1"}`), nil
				case "/api/issues/issue-1/triage":
					triages++
					return jsonResponse(200, `{"cached":false,"evidence_digest":"`+testDigest+`","ai_receipt_id":"ai-1"}`), nil
				case "/api/projects/project-1/ai-receipts/ai-1":
					receipts++
					return jsonResponse(200, tc.receipt), nil
				default:
					t.Fatalf("unexpected route %s", r.URL)
					return nil, nil
				}
			})
			flow := reactor.NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
			flow.SetSleep(func(time.Duration) {})
			if _, err := PrepareDraft(context.Background(), flow, testDraftConfig, parsedNotice(t), fixedClient(client)); !errors.Is(err, ErrReceiptMismatch) {
				t.Fatalf("receipt refusal = %v", err)
			}
			if triages != 1 || receipts != 1 {
				t.Fatalf("terminal evidence was retried: triage=%d receipts=%d", triages, receipts)
			}
		})
	}
}

func TestExactReceiptNotFoundIsBoundedPendingAndForbiddenIsTerminal(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var triages, receipts int
			client := testClient(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/api/issues/issue-1":
					return jsonResponse(200, `{"id":"issue-1","project_id":"project-1"}`), nil
				case "/api/issues/issue-1/triage":
					triages++
					return jsonResponse(200, `{"cached":false,"evidence_digest":"`+testDigest+`","ai_receipt_id":"ai-1"}`), nil
				case "/api/projects/project-1/ai-receipts/ai-1":
					receipts++
					if r.URL.RawQuery != "" {
						t.Fatal("exact receipt lookup must not use list pagination")
					}
					return jsonResponse(status, "untrusted private diagnostic"), nil
				default:
					t.Fatalf("receipt lookup escaped its exact path: %s", r.URL)
					return nil, nil
				}
			})
			flow := reactor.NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
			flow.SetSleep(func(time.Duration) {})
			_, err := PrepareDraft(context.Background(), flow, testDraftConfig, parsedNotice(t), fixedClient(client))
			wantReads := 1
			if status == http.StatusNotFound {
				wantReads = 4
			}
			if err == nil || errors.Is(err, ErrReceiptPending) != (status == http.StatusNotFound) || strings.Contains(err.Error(), "private diagnostic") || triages != 1 || receipts != wantReads {
				t.Fatalf("exact receipt status=%d err=%v triages=%d receipts=%d", status, err, triages, receipts)
			}
		})
	}
}

func TestFactoryScopeAndSecretErrorsAreRefusedBeforeHTTP(t *testing.T) {
	const secret = "sensitive-vault-diagnostic"
	httpCalls := 0
	noHTTP := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls++
		return nil, errors.New("unreviewed scope must not send a request")
	})}
	for _, tc := range []struct {
		name    string
		factory ClientFactory
	}{
		{"secret error", func(context.Context) (*Client, error) { return nil, errors.New(secret) }},
		{"nil client", func(context.Context) (*Client, error) { return nil, nil }},
		{"foreign origin", func(context.Context) (*Client, error) {
			return NewClient("https://other.example", "project-1", "credential", noHTTP)
		}},
		{"foreign project", func(context.Context) (*Client, error) {
			return NewClient("https://flare.example", "project-2", "credential", noHTTP)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := reactor.NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
			_, err := PrepareDraft(context.Background(), flow, testDraftConfig, parsedNotice(t), tc.factory)
			if err == nil || strings.Contains(err.Error(), secret) || httpCalls != 0 {
				t.Fatalf("unsafe factory result: %v", err)
			}
			encoded, marshalErr := json.Marshal(flow.Steps())
			if marshalErr != nil || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "credential") {
				t.Fatalf("factory diagnostic leaked into journal: %s, %v", encoded, marshalErr)
			}
		})
	}
}

func TestReviewedOriginChangeCannotReuseCompletedEvidence(t *testing.T) {
	var triages, receipts int
	client := successfulClient(t, &triages, &receipts)
	flow := reactor.NewInProcFlow(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := PrepareDraft(context.Background(), flow, testDraftConfig, parsedNotice(t), fixedClient(client)); err != nil {
		t.Fatal(err)
	}
	changed := testDraftConfig
	changed.BaseURL = "https://other.example"
	factoryCalls := 0
	_, err := PrepareDraft(context.Background(), flow, changed, parsedNotice(t), func(context.Context) (*Client, error) {
		factoryCalls++
		return nil, errors.New("new configuration needs its own authorization")
	})
	if err == nil || factoryCalls != 1 || triages != 1 || receipts != 1 {
		t.Fatalf("changed origin reused old evidence: err=%v factory=%d triage=%d receipts=%d", err, factoryCalls, triages, receipts)
	}
}

func TestAllResponseProjectionsHaveBoundsAndClientRedacts(t *testing.T) {
	for _, target := range []string{"triage", "receipts"} {
		t.Run(target, func(t *testing.T) {
			client := testClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/issues/issue-1" {
					return jsonResponse(200, `{"id":"issue-1","project_id":"project-1"}`), nil
				}
				limit := maxTriageBytes
				if target == "receipts" {
					limit = maxReceiptBytes
				}
				return jsonResponse(200, strings.Repeat(" ", limit+1)), nil
			})
			var err error
			if target == "triage" {
				_, err = client.TriageFresh(context.Background(), "issue-1")
			} else {
				_, err = client.ConfirmDraft(context.Background(), parsedNotice(t), FreshTriage{testDigest, "ai-1"})
			}
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("unbounded %s response: %v", target, err)
			}
		})
	}
	client := testClient(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("not used") })
	encoded, err := json.Marshal(client)
	for _, output := range []string{string(encoded), fmt.Sprintf("%v", client), fmt.Sprintf("%#v", client), fmt.Sprintf("%+v", *client)} {
		if err != nil || strings.Contains(output, "flb_test_token") || !strings.Contains(output, "REDACTED") {
			t.Fatalf("client formatting leaked credential: %s, %v", output, err)
		}
	}
}

// Exercise the real pipe SDK across new process sessions, with a small host
// journal stub preserving succeeded output. This verifies helper/SDK replay;
// it does not substitute for production supervisor/database acceptance.
func TestPipeRestartReplaysTriageThenDraftWithoutSecretReads(t *testing.T) {
	journal := make(map[string]json.RawMessage)
	var triages, receipts, factoryCalls int
	client := successfulClient(t, &triages, &receipts)
	factory := func(context.Context) (*Client, error) { factoryCalls++; return client, nil }
	var first Draft
	for session := 0; session < 3; session++ {
		hostIn, childOut := io.Pipe()
		childIn, hostOut := io.Pipe()
		closePipes := func() { _ = hostIn.Close(); _ = childOut.Close(); _ = childIn.Close(); _ = hostOut.Close() }
		flow := flowruntime.New(childIn, childOut, slog.New(slog.NewTextHandler(io.Discard, nil)))
		hostDone := make(chan error, 1)
		go func(interrupt bool) {
			defer closePipes()
			dec, enc := wire.NewDecoder(hostIn), wire.NewEncoder(hostOut)
			keys := make(map[int64]string)
			for {
				frame, err := dec.Decode()
				if err != nil {
					hostDone <- nil
					return
				}
				var kind wire.Kind
				var body any
				switch frame.Kind {
				case wire.KindStepStart:
					var start wire.StepStart
					if err := wire.Unwrap(frame, &start); err != nil {
						hostDone <- err
						return
					}
					wantMax := 1
					if start.StepName == "flare-confirm-draft" {
						wantMax = 4
					}
					if !start.DurableAttempts || start.MaxAttempts != wantMax || start.InputHash == "" || start.IdempotencyKey == "" {
						hostDone <- fmt.Errorf("unbound or unbounded step: %+v", start)
						return
					}
					if interrupt && start.StepName == "flare-confirm-draft" {
						hostDone <- nil
						return
					}
					key := fmt.Sprintf("%d/%s/%s/%s", start.Seq, start.StepName, start.IdempotencyKey, start.InputHash)
					keys[start.Seq] = key
					output, replay := journal[key]
					kind, body = wire.KindStepReply, wire.StepReply{Replay: replay, Output: output, Attempt: 1}
				case wire.KindStepEnd:
					var end wire.StepEnd
					if err := wire.Unwrap(frame, &end); err != nil {
						hostDone <- err
						return
					}
					if end.ErrorText != "" || len(end.Output) == 0 || keys[end.Seq] == "" {
						hostDone <- fmt.Errorf("unexpected evidence end: %+v", end)
						return
					}
					journal[keys[end.Seq]] = append(json.RawMessage(nil), end.Output...)
					kind = wire.KindAck
				default:
					hostDone <- fmt.Errorf("unexpected evidence frame %s", frame.Kind)
					return
				}
				reply, err := wire.Wrap(frame.ID+100, frame.ID, kind, body)
				if err == nil {
					err = enc.Encode(reply)
				}
				if err != nil {
					hostDone <- err
					return
				}
			}
		}(session == 0)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		draft, err := PrepareDraft(ctx, flow, testDraftConfig, parsedNotice(t), factory)
		cancel()
		closePipes()
		if hostErr := <-hostDone; hostErr != nil {
			t.Fatal(hostErr)
		}
		if session == 0 {
			if err == nil || triages != 1 || receipts != 0 || factoryCalls != 1 {
				t.Fatalf("interrupted session = %+v %v; calls=%d/%d/%d", draft, err, triages, receipts, factoryCalls)
			}
			continue
		}
		if err != nil || draft.Status != "draft" || triages != 1 || receipts != 1 || factoryCalls != 2 {
			t.Fatalf("restarted session %d = %+v %v; calls=%d/%d/%d", session, draft, err, triages, receipts, factoryCalls)
		}
		if session == 1 {
			first = draft
		} else if draft != first {
			t.Fatal("completed draft changed on full replay")
		}
	}
}
