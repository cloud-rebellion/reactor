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

func TestSalesforceIdentityURLAccountKeyValidation(t *testing.T) {
	const org = "00Dx0000000BV7z"
	for _, raw := range []string{
		"https://login.salesforce.com/id/" + org + "/005x00000012Q9P",
		"https://test.salesforce.com/id/" + org + "/005x00000012Q9P",
		"https://Acme.my.salesforce.com/id/" + org + "AAA/005x00000012Q9PAAA",
	} {
		got, err := salesforceOrgFromIdentityURL(raw)
		if err != nil || got != org {
			t.Fatalf("identity URL returned %q, %v; want org %q", got, err, org)
		}
	}
	for _, raw := range []string{
		"", "https://evil.test/id/" + org + "/005x00000012Q9P",
		"http://login.salesforce.com/id/" + org + "/005x00000012Q9P",
		"https://user@login.salesforce.com/id/" + org + "/005x00000012Q9P",
		"https://login.salesforce.com:443/id/" + org + "/005x00000012Q9P",
		"https://login.salesforce.com/id/" + org + "/005x00000012Q9P?x=1",
		"https://login.salesforce.com/id/" + org + "/005x00000012Q9P#fragment",
		"https://login.salesforce.com/id/%30%30Dx0000000BV7z/005x00000012Q9P",
		"https://login.salesforce.com/id/00Dx0000000BV7z/001x00000012Q9P",
		"https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P/extra",
		"https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P/",
	} {
		if got, err := salesforceOrgFromIdentityURL(raw); err == nil || got != "" {
			t.Fatalf("untrusted identity URL accepted: %q", raw)
		}
	}
	if salesforceAccountKey(org) == salesforceAccountKey("00Dx0000000BV7y") {
		t.Fatal("different orgs share a budget key")
	}
}

func TestSalesforceBrokerSessionSharesOrgKeyWithoutExposingOrgID(t *testing.T) {
	st := salesforceStore(t)
	ctx := context.Background()
	const identity = "https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P"
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"initial-token","instance_url":"https://acme.my.salesforce.com","id":"` + identity + `"}`)), Request: r}, nil
	})}
	conn, err := st.CompleteAuth(ctx, startSalesforceAuth(t, st), "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	token, origin, key, err := st.SalesforceBrokerSession(ctx, conn.ID, "acme")
	if err != nil || token != "initial-token" || origin != "https://acme.my.salesforce.com" ||
		key != salesforceAccountKey("00Dx0000000BV7z") {
		t.Fatalf("broker session token/origin/account key invalid: token present=%v origin=%q key=%q err=%v", token != "", origin, key, err)
	}
	if token, origin, key, err := st.SalesforceBrokerSession(ctx, conn.ID, "other"); !errors.Is(err, ErrNotFound) || token != "" || origin != "" || key != "" {
		t.Fatalf("foreign tenant broker session escaped: %v", err)
	}
	second, err := st.upsertConnection(ctx, "acme", "salesforce", "Second", "operator", tokenBlob{
		AccessToken: "another-user", SalesforceAPIOrigin: "https://other.my.salesforce.com",
		SalesforceOrgID: "00Dx0000000BV7z",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, secondKey, err := st.SalesforceBrokerSession(ctx, second.ID, "acme")
	if err != nil || secondKey != key {
		t.Fatalf("same org via second connection has different key: %q, %v", secondKey, err)
	}
	var encrypted []byte
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", conn.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("00Dx0000000BV7z")) || bytes.Contains(encrypted, []byte("initial-token")) {
		t.Fatal("Salesforce account identity or token stored in plaintext")
	}
	legacy, err := st.upsertConnection(ctx, "acme", "salesforce", "Legacy", "operator", tokenBlob{
		AccessToken: "legacy", SalesforceAPIOrigin: "https://legacy.my.salesforce.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.SalesforceBrokerSession(ctx, legacy.ID, "acme"); !errors.Is(err, ErrSalesforceOrgIDUnavailable) {
		t.Fatalf("legacy connection without org identity was brokered: %v", err)
	}
}

func TestSalesforceBrokerSessionCurrentRejectsReconnectAndDisable(t *testing.T) {
	st := salesforceStore(t)
	ctx := context.Background()
	const firstOrigin = "https://acme.my.salesforce.com"
	const secondOrigin = "https://other.my.salesforce.com"
	const org = "00Dx0000000BV7z"
	conn, err := st.upsertConnection(ctx, "acme", "salesforce", "Main", "operator", tokenBlob{
		AccessToken: "old-secret-token", SalesforceAPIOrigin: firstOrigin, SalesforceOrgID: org,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, origin, key, err := st.SalesforceBrokerSession(ctx, conn.ID, "acme")
	if err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		current, err := st.SalesforceBrokerSessionCurrent(ctx, conn.ID, "acme", token, origin, key)
		if err != nil || current != want {
			t.Fatalf("session current = %v, %v; want %v", current, err, want)
		}
	}
	check(true)
	if _, err := st.upsertConnection(ctx, "acme", "salesforce", "Main", "operator", tokenBlob{
		AccessToken: "new-secret-token", SalesforceAPIOrigin: firstOrigin, SalesforceOrgID: org,
	}); err != nil {
		t.Fatal(err)
	}
	check(false)
	token, origin, key, err = st.SalesforceBrokerSession(ctx, conn.ID, "acme")
	if err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err := st.upsertConnection(ctx, "acme", "salesforce", "Main", "operator", tokenBlob{
		AccessToken: "new-secret-token", SalesforceAPIOrigin: secondOrigin, SalesforceOrgID: org,
	}); err != nil {
		t.Fatal(err)
	}
	check(false)
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_providers SET enabled = 0 WHERE provider_id = 'salesforce'"); err != nil {
		t.Fatal(err)
	}
	check(false)
	if current, err := st.SalesforceBrokerSessionCurrent(ctx, conn.ID, "other", token, origin, key); err != nil || current {
		t.Fatalf("foreign tenant current = %v, %v", current, err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_providers SET enabled = 1 WHERE provider_id = 'salesforce'"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE oauth_connections SET token_encrypted = ? WHERE id = ?", []byte("corrupt"), conn.ID); err != nil {
		t.Fatal(err)
	}
	if current, err := st.SalesforceBrokerSessionCurrent(ctx, conn.ID, "acme", token, origin, key); current || err == nil ||
		strings.Contains(err.Error(), "new-secret-token") || strings.Contains(err.Error(), "old-secret-token") {
		t.Fatalf("corrupt ciphertext result = %v, %v", current, err)
	}
}

func TestSalesforceRefreshCannotChangeOrganizationIdentity(t *testing.T) {
	st := salesforceStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	conn, err := st.upsertConnection(ctx, "acme", "salesforce", "Main", "operator", tokenBlob{
		AccessToken: "old", RefreshToken: "refresh", Expiry: now.Add(-time.Minute),
		SalesforceAPIOrigin: "https://acme.my.salesforce.com", SalesforceOrgID: "00Dx0000000BV7z",
	})
	if err != nil {
		t.Fatal(err)
	}
	var before, after []byte
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", conn.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	st.http = &http.Client{Transport: tokenResponseTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"changed","instance_url":"https://other.my.salesforce.com","id":"https://login.salesforce.com/id/00Dx0000000BV7y/005x00000012Q9P","expires_in":3600}`)), Request: r}, nil
	})}
	if token, err := st.Token(ctx, conn.ID, "acme"); err == nil || token != "" {
		t.Fatalf("changed-org refresh issued token: present=%v err=%v", token != "", err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT token_encrypted FROM oauth_connections WHERE id = ?", conn.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("changed-org refresh replaced the previous encrypted session")
	}
}
