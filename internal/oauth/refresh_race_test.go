package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testOAuthProvider(t *testing.T, st *Store) {
	t.Helper()
	if err := st.UpsertProvider(context.Background(), Provider{
		ProviderID: "provider", Name: "Provider", AuthURL: "https://provider.example/auth",
		TokenURL: "https://provider.example/token", ClientID: "client", Enabled: true,
	}, ""); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectReturnsExistingConnectionID(t *testing.T) {
	st := newTestStore(t)
	testOAuthProvider(t, st)
	ctx := context.Background()
	first, err := st.upsertConnection(ctx, "acme", "provider", "account", "original-user", tokenBlob{AccessToken: "first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.upsertConnection(ctx, "acme", "provider", "account", "later-user", tokenBlob{AccessToken: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.CreatedBy != "original-user" || !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("reconnect returned a non-durable identity: first=%+v second=%+v", first, second)
	}
	got, err := st.Token(ctx, second.ID, "acme")
	if err != nil || got != "second" {
		t.Fatalf("reconnected token = %q, %v", got, err)
	}
}

func TestExpiringOAuthTokenWithoutRefreshRequiresReconnect(t *testing.T) {
	st := newTestStore(t)
	testOAuthProvider(t, st)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	conn, err := st.upsertConnection(ctx, "acme", "provider", "account", "operator", tokenBlob{
		AccessToken: "nearly-expired", Expiry: now.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Token(ctx, conn.ID, "acme")
	if got != "" || err == nil || !strings.Contains(err.Error(), "reconnect") {
		t.Fatalf("expiring token was returned: token=%q err=%v", got, err)
	}
	rows, err := st.ListConnections(ctx, "acme")
	if err != nil || len(rows) != 1 || rows[0].Status != "error" {
		t.Fatalf("expiring connection status = %+v, %v", rows, err)
	}
}

func TestRefreshCannotOverwriteReconnectOrResurrectDeletion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(context.Context, *Store, Connection) error
		want     string
		wantGone bool
	}{
		{
			name: "reconnect",
			mutate: func(ctx context.Context, st *Store, _ Connection) error {
				_, err := st.upsertConnection(ctx, "acme", "provider", "account", "new-user", tokenBlob{
					AccessToken: "reconnected", RefreshToken: "new-refresh", Expiry: st.now().Add(time.Hour),
				})
				return err
			},
			want: "reconnected",
		},
		{
			name: "delete",
			mutate: func(ctx context.Context, st *Store, conn Connection) error {
				return st.DeleteConnection(ctx, conn.ID, "acme")
			},
			wantGone: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			testOAuthProvider(t, st)
			ctx := context.Background()
			now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
			st.now = func() time.Time { return now }
			conn, err := st.upsertConnection(ctx, "acme", "provider", "account", "original-user", tokenBlob{
				AccessToken: "expired", RefreshToken: "old-refresh", Expiry: now.Add(-time.Minute),
			})
			if err != nil {
				t.Fatal(err)
			}
			st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
				if err := tc.mutate(ctx, st, conn); err != nil {
					t.Errorf("mutate during refresh: %v", err)
					return nil, err
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"access_token":"stale-refresh","refresh_token":"stale-rotation","expires_in":3600}`)), Request: r}, nil
			})}
			got, err := st.Token(ctx, conn.ID, "acme")
			if tc.wantGone {
				if !errors.Is(err, ErrNotFound) || got != "" {
					t.Fatalf("deleted connection was resurrected: token=%q err=%v", got, err)
				}
				if rows, _, err := st.ListConnectionsPage(ctx, "acme", "", 10, 0); err != nil || len(rows) != 0 {
					t.Fatalf("deleted connection reappeared: rows=%+v err=%v", rows, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("refresh replaced a newer connection: token=%q err=%v", got, err)
			}
			stored, err := st.Token(ctx, conn.ID, "acme")
			if err != nil || stored != tc.want {
				t.Fatalf("stored token = %q, %v; want newer connection", stored, err)
			}
		})
	}
}

func TestFailedOldRefreshCannotMarkReconnectedAccountBroken(t *testing.T) {
	st := newTestStore(t)
	testOAuthProvider(t, st)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	conn, err := st.upsertConnection(ctx, "acme", "provider", "account", "original-user", tokenBlob{
		AccessToken: "expired", RefreshToken: "old-refresh", Expiry: now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		if _, err := st.upsertConnection(ctx, "acme", "provider", "account", "new-user", tokenBlob{
			AccessToken: "reconnected", RefreshToken: "new-refresh", Expiry: now.Add(time.Hour),
		}); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)), Request: r}, nil
	})}
	got, err := st.Token(ctx, conn.ID, "acme")
	if err != nil || got != "reconnected" {
		t.Fatalf("old refresh error hid a new account token: token=%q err=%v", got, err)
	}
	rows, err := st.ListConnections(ctx, "acme")
	if err != nil || len(rows) != 1 || rows[0].Status != "connected" {
		t.Fatalf("reconnected account status = %+v, %v", rows, err)
	}
}

func TestConcurrentTokenCallsShareOneRefresh(t *testing.T) {
	st := newTestStore(t)
	testOAuthProvider(t, st)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	conn, err := st.upsertConnection(ctx, "acme", "provider", "account", "operator", tokenBlob{
		AccessToken: "expired", RefreshToken: "rotating-refresh", Expiry: now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var exchanges atomic.Int32
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		if exchanges.Add(1) == 1 {
			close(entered)
			<-release
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"fresh","refresh_token":"rotated-refresh","expires_in":3600}`)), Request: r}, nil
	})}
	result := make(chan struct {
		token string
		err   error
	}, 2)
	go func() {
		token, err := st.Token(ctx, conn.ID, "acme")
		result <- struct {
			token string
			err   error
		}{token, err}
	}()
	<-entered
	go func() {
		token, err := st.Token(ctx, conn.ID, "acme")
		result <- struct {
			token string
			err   error
		}{token, err}
	}()
	// Give the second caller time to reach the expired row while the first
	// provider request remains blocked. Without a refresh gate it exchanges
	// the same rotating token and the counter becomes two.
	time.Sleep(30 * time.Millisecond)
	close(release)
	for i := 0; i < 2; i++ {
		got := <-result
		if got.err != nil || got.token != "fresh" {
			t.Fatalf("concurrent token result = %+v", got)
		}
	}
	if exchanges.Load() != 1 {
		t.Fatalf("rotating token exchanged %d times; want once", exchanges.Load())
	}
}

func TestOAuthStateIsConsumedByOnlyOneConcurrentCallback(t *testing.T) {
	st := newTestStore(t)
	testOAuthProvider(t, st)
	ctx := context.Background()
	var exchanges atomic.Int32
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		exchanges.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"token","expires_in":3600}`)), Request: r}, nil
	})}
	authURL, err := st.StartAuth(ctx, "acme", "provider", "account", "https://reactor.example/oauth/callback", "operator")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := st.CompleteAuth(ctx, state, "same-code")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 || exchanges.Load() != 1 {
		t.Fatalf("concurrent state reuse: successes=%d token_exchanges=%d", succeeded, exchanges.Load())
	}
}
