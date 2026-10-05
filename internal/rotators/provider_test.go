package rotators

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSharedSecretProducesHexBytes(t *testing.T) {
	t.Parallel()
	p := &SharedSecretProvider{}
	got, err := p.Rotate(context.Background(), "ignored", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("len = %d, want 64 hex chars", len(got))
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("not hex: %v", err)
	}
	// Two calls must differ; if rand.Read isn't wired this would fail.
	other, _ := p.Rotate(context.Background(), "ignored", nil)
	if got == other {
		t.Fatal("two calls produced the same value (rand wired wrong)")
	}
}

func TestSharedSecretValidate(t *testing.T) {
	t.Parallel()
	p := &SharedSecretProvider{}
	ok, _ := p.Validate(context.Background(), "abc", nil)
	if !ok {
		t.Fatal("non-empty key should validate")
	}
	ok, _ = p.Validate(context.Background(), "", nil)
	if ok {
		t.Fatal("empty key should not validate")
	}
}

func TestManualRotationRefuses(t *testing.T) {
	t.Parallel()
	p := &ManualProvider{}
	if p.CanAutoRotate() {
		t.Fatal("manual provider must not auto-rotate")
	}
	if _, err := p.Rotate(context.Background(), "x", nil); err == nil {
		t.Fatal("manual rotate must error")
	}
}

func TestRegistryHasBuiltins(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"cloudflare", "shared-secret", "manual"} {
		if _, err := Get(name); err != nil {
			t.Fatalf("missing built-in %q", name)
		}
	}
	if _, err := Get("nope"); err == nil {
		t.Fatal("unknown provider must error")
	}
}

// TestCloudflareRotateHappyPath drives the Cloudflare provider against
// a fake API server. Verifies the provider hits /verify, then PUTs to
// /tokens/{id}/value, and returns the new bearer.
func TestCloudflareRotateHappyPath(t *testing.T) {
	t.Parallel()

	hits := struct {
		verify int
		roll   int
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/user/tokens/verify"):
			hits.verify++
			if r.Header.Get("Authorization") != "Bearer current-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"tok_abc"}}`))
		case strings.HasSuffix(r.URL.Path, "/user/tokens/tok_abc/value") && r.Method == http.MethodPut:
			hits.roll++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":"new-rolled-token","errors":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := &CloudflareProvider{APIBase: srv.URL + "/client/v4"}
	got, err := p.Rotate(context.Background(), "current-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "new-rolled-token" {
		t.Fatalf("got %q, want new-rolled-token", got)
	}
	if hits.verify == 0 || hits.roll == 0 {
		t.Fatalf("expected verify+roll hits, got %+v", hits)
	}
}

func TestCloudflareValidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"x"}}`))
	}))
	defer srv.Close()

	ok, err := (&CloudflareProvider{APIBase: srv.URL + "/client/v4"}).Validate(context.Background(), "any", nil)
	if err != nil || !ok {
		t.Fatalf("validate failed: ok=%v err=%v", ok, err)
	}
}

func TestCloudflareProviderRejectsLinkLocalAPIBase(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := (&CloudflareProvider{APIBase: "http://169.254.169.254"}).Validate(ctx, "any", nil)
	if err == nil || !strings.Contains(err.Error(), "ssrf") {
		t.Fatalf("metadata API base error = %v, want SSRF refusal", err)
	}
}
