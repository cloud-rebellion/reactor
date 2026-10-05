package mollie

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

func TestDryRunBlocksPaymentConnectorBeforeNetwork(t *testing.T) {
	t.Setenv("REACTOR_MODE", "dry_run")
	old := baseURL
	baseURL = "http://127.0.0.1:1/v2"
	t.Cleanup(func() { baseURL = old })
	c := &Client{Key: "test_abc"}
	params := PaymentParams{Amount: Amount{Currency: "EUR", Value: "10.00"}, Description: "Order", RedirectURL: "https://example.test/return"}
	if _, err := c.CreatePayment(context.Background(), params); !errors.Is(err, ahttp.ErrDryRun) {
		t.Fatalf("payment dry-run error = %v, want ErrDryRun", err)
	}
	if _, err := c.CreateRefund(context.Background(), "tr_1", Amount{}); !errors.Is(err, ahttp.ErrDryRun) {
		t.Fatalf("refund dry-run error = %v, want ErrDryRun", err)
	}
}

func fake(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	old := baseURL
	baseURL = srv.URL
	t.Cleanup(func() { baseURL = old })
	return &Client{Key: "test_abc"}
}

func TestCreatePayment(t *testing.T) {
	var body map[string]any
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/payments" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test_abc" {
			t.Errorf("bad auth %q", r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"tr_1","status":"open","_links":{"checkout":{"href":"https://www.mollie.com/checkout/tr_1"}}}`)
	})
	pay, err := c.CreatePayment(context.Background(), PaymentParams{
		Amount: Amount{Currency: "EUR", Value: "10.00"}, Description: "Order 1", RedirectURL: "https://x/return",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pay.ID != "tr_1" || pay.Status != "open" || pay.CheckoutURL != "https://www.mollie.com/checkout/tr_1" {
		t.Fatalf("unexpected payment %+v", pay)
	}
	amt, _ := body["amount"].(map[string]any)
	if amt["currency"] != "EUR" || amt["value"] != "10.00" || body["description"] != "Order 1" {
		t.Fatalf("bad request body %v", body)
	}
}

func TestGetPayment(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/payments/tr_9" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"tr_9","status":"paid","_links":{"checkout":{"href":""}}}`)
	})
	pay, err := c.GetPayment(context.Background(), "tr_9")
	if err != nil || pay.Status != "paid" {
		t.Fatalf("payment: %+v %v", pay, err)
	}
}

func TestValidation(t *testing.T) {
	c := &Client{Key: "k"}
	if _, err := c.CreatePayment(context.Background(), PaymentParams{Description: "x", RedirectURL: "y"}); err == nil {
		t.Fatal("want error with no amount")
	}
	if _, err := c.GetPayment(context.Background(), ""); err == nil {
		t.Fatal("want error with empty id")
	}
}
