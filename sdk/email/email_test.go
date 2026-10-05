package email

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

func TestDryRunBlocksEmailConnectorsBeforeNetwork(t *testing.T) {
	t.Setenv("REACTOR_MODE", "dry_run")
	msg := Message{From: "me@example.com", To: []string{"customer@example.com"}, Subject: "Review", Text: "fixture"}
	if _, err := SendGmail(context.Background(), "token", msg); !errors.Is(err, ahttp.ErrDryRun) {
		t.Fatalf("gmail dry-run error = %v, want ErrDryRun", err)
	}
	if err := SendOutlook(context.Background(), "token", msg); !errors.Is(err, ahttp.ErrDryRun) {
		t.Fatalf("outlook dry-run error = %v, want ErrDryRun", err)
	}
}

func TestSendConnectedUsesBoundHostWithoutRawTokenFallback(t *testing.T) {
	msg := Message{From: "me@example.com", To: []string{"customer@example.com"}, Text: "hello"}
	if _, err := SendConnected(context.Background(), "oauth:conn_1", msg); !errors.Is(err, ErrMailBrokerUnavailable) {
		t.Fatalf("unbound mail send = %v", err)
	}
	calls := 0
	restore := BindMailSender(func(_ context.Context, ref string, got Message) (string, error) {
		calls++
		if ref != "oauth:conn_1" || got.Text != msg.Text {
			t.Errorf("mail request = %q %+v", ref, got)
		}
		return "msg_1", nil
	})
	defer restore()
	if id, err := SendConnected(context.Background(), "oauth:conn_1", msg); err != nil || id != "msg_1" || calls != 1 {
		t.Fatalf("connected mail result = %q, %v; calls=%d", id, err, calls)
	}
	if _, err := SendConnected(context.Background(), "conn_1", msg); err == nil || calls != 1 {
		t.Fatalf("invalid ref reached host: %v; calls=%d", err, calls)
	}
	t.Setenv("REACTOR_MODE", "dry_run")
	if _, err := SendConnected(context.Background(), "oauth:conn_1", msg); !errors.Is(err, ahttp.ErrDryRun) || calls != 1 {
		t.Fatalf("dry-run mail = %v; calls=%d", err, calls)
	}
}

func TestRFC822_TextOnly(t *testing.T) {
	m := Message{From: "me@x.com", To: []string{"a@y.com", "b@y.com"}, Subject: "Hi", Text: "hello"}
	raw, err := m.rfc822()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"From: me@x.com\r\n", "To: a@y.com, b@y.com\r\n", "Subject: Hi\r\n", `text/plain; charset="UTF-8"`, "hello"} {
		if !strings.Contains(s, want) {
			t.Fatalf("rfc822 missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "multipart") {
		t.Fatal("text-only should not be multipart")
	}
}

func TestRFC822_Multipart(t *testing.T) {
	m := Message{From: "me@x.com", To: []string{"a@y.com"}, Subject: "Hi", Text: "plain", HTML: "<b>rich</b>"}
	raw, err := m.rfc822()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"multipart/alternative; boundary=", "text/plain", "text/html", "plain", "rich"} {
		if !strings.Contains(s, want) {
			t.Fatalf("multipart rfc822 missing %q", want)
		}
	}
	// Deterministic boundary: same content -> same bytes.
	raw2, _ := m.rfc822()
	if string(raw2) != s {
		t.Fatal("rfc822 is not deterministic for identical input")
	}
}

func TestRFC822_RequiresFromToBody(t *testing.T) {
	for _, m := range []Message{
		{To: []string{"a@y.com"}, Text: "x"},
		{From: "me@x.com", Text: "x"},
		{From: "me@x.com", To: []string{"a@y.com"}},
	} {
		if _, err := m.rfc822(); err == nil {
			t.Fatalf("expected error for %+v", m)
		}
	}
}

func TestRFC822RejectsHeaderInjection(t *testing.T) {
	t.Parallel()
	cases := []Message{
		{From: "me@example.com\r\nBcc: attacker@example.com", To: []string{"customer@example.com"}, Text: "body"},
		{From: "me@example.com", To: []string{"customer@example.com\nBcc: attacker@example.com"}, Text: "body"},
		{From: "me@example.com", To: []string{"customer@example.com"}, Cc: []string{"copy@example.com\r\nBcc: attacker@example.com"}, Text: "body"},
		{From: "me@example.com", To: []string{"customer@example.com"}, Subject: "hello\r\nBcc: attacker@example.com", Text: "body"},
	}
	for _, msg := range cases {
		if _, err := msg.rfc822(); err == nil || !strings.Contains(err.Error(), "forbidden header") {
			t.Fatalf("header injection message returned %v", err)
		}
	}
}

func TestSendGmail(t *testing.T) {
	var gotRaw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			t.Errorf("missing bearer, got %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Raw string `json:"raw"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		dec, _ := base64.URLEncoding.DecodeString(body.Raw)
		gotRaw = string(dec)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_42"}`)
	}))
	defer srv.Close()
	old := gmailSendURL
	gmailSendURL = srv.URL
	defer func() { gmailSendURL = old }()

	id, err := SendGmail(context.Background(), "tok123", Message{
		From: "me@x.com", To: []string{"c@y.com"}, Subject: "Yo", Text: "body",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "msg_42" {
		t.Fatalf("id = %q, want msg_42", id)
	}
	if !strings.Contains(gotRaw, "To: c@y.com") || !strings.Contains(gotRaw, "body") {
		t.Fatalf("server got unexpected raw:\n%s", gotRaw)
	}
}

func TestSendOutlook(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tokAbc" {
			t.Errorf("missing bearer")
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusAccepted) // 202, no body
	}))
	defer srv.Close()
	old := graphSendURL
	graphSendURL = srv.URL
	defer func() { graphSendURL = old }()

	err := SendOutlook(context.Background(), "tokAbc", Message{
		From: "me@x.com", To: []string{"c@y.com"}, Cc: []string{"d@y.com"}, Subject: "Yo", HTML: "<p>hi</p>",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := payload["message"].(map[string]any)
	if msg == nil || msg["subject"] != "Yo" {
		t.Fatalf("bad graph payload: %+v", payload)
	}
	body, _ := msg["body"].(map[string]any)
	if body["contentType"] != "HTML" {
		t.Fatalf("want HTML contentType, got %v", body["contentType"])
	}
	to, _ := msg["toRecipients"].([]any)
	if len(to) != 1 {
		t.Fatalf("want 1 recipient, got %v", msg["toRecipients"])
	}
}

func TestSendDispatch(t *testing.T) {
	if _, err := Send(context.Background(), "yahoo", "t", Message{From: "a", To: []string{"b"}, Text: "x"}); err == nil {
		t.Fatal("unsupported provider should error")
	}
}

func TestEmptyToken(t *testing.T) {
	if _, err := SendGmail(context.Background(), "", Message{}); err == nil {
		t.Fatal("empty token should error")
	}
	if err := SendOutlook(context.Background(), "", Message{}); err == nil {
		t.Fatal("empty token should error")
	}
}
