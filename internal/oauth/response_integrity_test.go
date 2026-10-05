package oauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type tokenResponseTransport func(*http.Request) (*http.Response, error)

func (f tokenResponseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type tokenReadFailure struct{}

func (tokenReadFailure) Read([]byte) (int, error) {
	return 0, errors.New("synthetic-sensitive-read-error")
}

// Exercise the public refresh accessor and the encrypted row, not just a
// reader helper: valid prefixes must never replace a working token pair.
func TestTokenRefreshResponseIntegrity(t *testing.T) {
	const limit = 1 << 20
	const jsonToken = "{\"access_token\":\"replacement\",\"expires_in\":3600}"
	for _, tc := range []struct {
		name      string
		body      string
		broken    bool
		wantError string
	}{
		{"oversized form token", "access_token=" + strings.Repeat("x", limit), false, "exceeds"},
		{"oversized JSON with valid prefix", jsonToken + strings.Repeat(" ", limit), false, "exceeds"},
		{"interrupted JSON after valid prefix", jsonToken, true, "read token response"},
		{"interrupted form after valid prefix", "access_token=replacement", true, "read token response"},
		{"JSON exactly at limit", jsonToken + strings.Repeat(" ", limit-len(jsonToken)), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			ctx := context.Background()
			now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
			st.now = func() time.Time { return now }
			if err := st.UpsertProvider(ctx, Provider{
				ProviderID: "fixture", AuthURL: "https://provider.example/auth",
				TokenURL: "https://provider.example/token", Enabled: true,
			}, ""); err != nil {
				t.Fatal(err)
			}
			conn, err := st.upsertConnection(ctx, "acme", "fixture", "fixture", "", tokenBlob{
				AccessToken: "original", RefreshToken: "original-refresh", TokenType: "Bearer",
				Scope: "read write", Expiry: now.Add(-time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			stored := func() ([]byte, string) {
				t.Helper()
				var encrypted []byte
				var status string
				if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted, status FROM oauth_connections WHERE id = ?", conn.ID).Scan(&encrypted, &status); err != nil {
					t.Fatal(err)
				}
				return encrypted, status
			}
			before, _ := stored()
			st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
				var body io.Reader = strings.NewReader(tc.body)
				if tc.broken {
					body = io.MultiReader(body, tokenReadFailure{})
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(body), Request: r}, nil
			})}
			got, err := st.Token(ctx, conn.ID, "acme")
			after, status := stored()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("refresh error = %v, want %q", err, tc.wantError)
				}
				if strings.Contains(err.Error(), "synthetic-sensitive") || got != "" {
					t.Fatal("failed response exposed token or reader error detail")
				}
				if !bytes.Equal(before, after) || status != "error" {
					t.Fatal("failed refresh must preserve encrypted tokens and mark connection error")
				}
				return
			}
			if err != nil || got != "replacement" || status != "connected" {
				t.Fatalf("complete response rejected: %v (status %s)", err, status)
			}
			tok, err := st.loadTokenBlob(after, connectionTokenIdentity("acme", "fixture", "fixture"))
			if err != nil || tok.RefreshToken != "original-refresh" || tok.TokenType != "Bearer" || tok.Scope != "read write" || !tok.Expiry.Equal(now.Add(time.Hour)) {
				t.Fatal("successful refresh failed to preserve omitted token fields or update expiry")
			}
		})
	}
}
