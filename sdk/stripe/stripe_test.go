package stripe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

func TestDryRunBlocksPaymentConnectorBeforeNetwork(t *testing.T) {
	t.Setenv("REACTOR_MODE", "dry_run")
	old := baseURL
	baseURL = "http://127.0.0.1:1/v1"
	t.Cleanup(func() { baseURL = old })
	c := &Client{Key: "sk_test_123"}
	if _, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{LineItems: []LineItem{{Price: "price_x", Quantity: 1}}}, "idem"); !errors.Is(err, ahttp.ErrDryRun) {
		t.Fatalf("checkout dry-run error = %v, want ErrDryRun", err)
	}
	if _, err := c.CreateRefund(context.Background(), "pi_1", 0, "idem"); !errors.Is(err, ahttp.ErrDryRun) {
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
	return &Client{Key: "sk_test_123"}
}

func TestCreateCheckoutSession(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/checkout/sessions" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk_test_123" {
			t.Errorf("bad auth %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Idempotency-Key") != "idem-1" {
			t.Errorf("missing idempotency-key, got %q", r.Header.Get("Idempotency-Key"))
		}
		_ = r.ParseForm()
		if r.PostForm.Get("mode") != "payment" ||
			r.PostForm.Get("line_items[0][price]") != "price_x" ||
			r.PostForm.Get("line_items[0][quantity]") != "2" ||
			r.PostForm.Get("success_url") != "https://x/ok" {
			t.Errorf("bad form: %v", r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cs_1","url":"https://checkout.stripe.com/c/pay/cs_1","status":"open","payment_status":"unpaid"}`)
	})
	sess, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{
		Mode: "payment", SuccessURL: "https://x/ok", CancelURL: "https://x/no",
		LineItems: []LineItem{{Price: "price_x", Quantity: 2}},
	}, "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID != "cs_1" || !strings.HasPrefix(sess.URL, "https://checkout.stripe.com") {
		t.Fatalf("unexpected session %+v", sess)
	}
}

func TestCreateCustomerAndRefund(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/customers":
			if r.PostForm.Get("email") != "a@b.com" {
				t.Errorf("bad customer form %v", r.PostForm)
			}
			_, _ = io.WriteString(w, `{"id":"cus_1","email":"a@b.com","name":"Ada"}`)
		case "/refunds":
			if r.PostForm.Get("payment_intent") != "pi_1" || r.PostForm.Get("amount") != "500" {
				t.Errorf("bad refund form %v", r.PostForm)
			}
			_, _ = io.WriteString(w, `{"id":"re_1","status":"succeeded","amount":500}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	cust, err := c.CreateCustomer(context.Background(), CustomerParams{Email: "a@b.com", Name: "Ada"}, "ik")
	if err != nil || cust.ID != "cus_1" {
		t.Fatalf("customer: %+v %v", cust, err)
	}
	ref, err := c.CreateRefund(context.Background(), "pi_1", 500, "ik2")
	if err != nil || ref.ID != "re_1" || ref.Amount != 500 {
		t.Fatalf("refund: %+v %v", ref, err)
	}
}

func TestGetPaymentIntent(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/payment_intents/pi_9" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"pi_9","status":"succeeded","amount":1999,"currency":"eur"}`)
	})
	pi, err := c.GetPaymentIntent(context.Background(), "pi_9")
	if err != nil || pi.Status != "succeeded" || pi.Amount != 1999 {
		t.Fatalf("pi: %+v %v", pi, err)
	}
}

func TestNon2xxErrors(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, `{"error":{"message":"card declined"}}`)
	})
	_, err := c.CreateCustomer(context.Background(), CustomerParams{Email: "x@y.com"}, "")
	if err == nil || !strings.Contains(err.Error(), "402") {
		t.Fatalf("want 402 error, got %v", err)
	}
}

func TestProviderErrorBodyStaysOutOfStripeStepError(t *testing.T) {
	const private = "provider-echoed-customer-and-secret-canary"
	c := fake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, `{"error":{"message":"`+private+`"}}`)
	})
	_, err := c.CreateCustomer(context.Background(), CustomerParams{Email: "customer@example.test"}, "idem")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusPaymentRequired {
		t.Fatalf("provider failure classification = %v, want typed HTTP 402", err)
	}
	if strings.Contains(err.Error(), private) {
		t.Fatal("provider response body leaked into loggable Step error")
	}
}

func TestCheckoutRequiresLineItems(t *testing.T) {
	c := &Client{Key: "sk"}
	if _, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{}, ""); err == nil {
		t.Fatal("want error with no line items")
	}
}
