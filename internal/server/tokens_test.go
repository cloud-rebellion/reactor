package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTokenMintRequiresResolvedBrowserSession(t *testing.T) {
	t.Parallel()
	base, _, store, cleanup := newAuthServer(t, false)
	defer cleanup()

	ctx := context.Background()
	userID := lookupUserID(t, store, "alice")
	bearer, _, err := store.MintAPIToken(ctx, userID, "existing", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	post := func(t *testing.T, name string, credential func(*http.Request)) *http.Response {
		t.Helper()
		form := url.Values{"name": {name}, "ttl_days": {"1"}}
		req, err := http.NewRequest(http.MethodPost, base+"/tokens", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", base) // Pass CSRF so the token handler decides.
		credential(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	for _, tc := range []struct {
		name       string
		credential func(*http.Request)
	}{
		{"bearer", func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+bearer) }},
		{"basic", func(req *http.Request) { req.SetBasicAuth("alice", "secret-pass") }},
		{"invalid session plus bearer", func(req *http.Request) {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "invalid"})
			req.Header.Set("Authorization", "Bearer "+bearer)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(t, "from-"+tc.name, tc.credential)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want 403; body = %q", resp.StatusCode, body)
			}
			tokens, err := store.ListAPITokens(ctx, userID)
			if err != nil || len(tokens) != 1 {
				t.Fatalf("token count after denied request = %d, err = %v; want 1", len(tokens), err)
			}
		})
	}

	session, err := store.CreateSession(ctx, userID, "test", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp := post(t, "browser", func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/tokens" {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("browser mint status = %d, location = %q, body = %q; want 303 /tokens", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	tokens, err := store.ListAPITokens(ctx, userID)
	if err != nil || len(tokens) != 2 {
		t.Fatalf("token count after browser mint = %d, err = %v; want 2", len(tokens), err)
	}

	// A bearer remains valid for existing read APIs after losing mint authority.
	getReq, err := http.NewRequest(http.MethodGet, base+"/tokens", nil)
	if err != nil {
		t.Fatal(err)
	}
	getReq.Header.Set("Authorization", "Bearer "+bearer)
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("bearer token list status = %d, want 200", getResp.StatusCode)
	}
}
