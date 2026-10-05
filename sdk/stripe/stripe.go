// Package stripe is the workflow-side Stripe connector. AI-generated workflows
// call it from inside a Step closure to take payments, create customers, and
// issue refunds. The secret key lives in the vault and is fetched at run time:
//
//	c := &stripe.Client{Key: string(vault.MustGet("stripe-key").Reveal())}
//	sess, err := c.CreateCheckoutSession(ctx, stripe.CheckoutParams{
//		Mode: "payment", SuccessURL: "https://x/ok", CancelURL: "https://x/no",
//		LineItems: []stripe.LineItem{{Price: "price_123", Quantity: 1}},
//	}, idemKey)
//
// Stripe takes form-encoded bodies and an Idempotency-Key header; pass the
// Step's idempotency key through so a replay does not double-charge.
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

// baseURL is package-owned so workflow input cannot redirect a Stripe key to
// another origin. Tests in this package can point it at a fake server.
var baseURL = "https://api.stripe.com/v1"

// Client holds the Stripe secret key (sk_...).
type Client struct {
	Key string
}

// APIError classifies a failed Stripe response by HTTP status. Provider error
// bodies are untrusted and may echo credentials or customer data, so they are
// never copied into its loggable text.
type APIError struct{ Status int }

func (e *APIError) Error() string {
	if e == nil {
		return "stripe: HTTP error"
	}
	return fmt.Sprintf("stripe: HTTP %d", e.Status)
}

// Customer is the subset of a Stripe customer workflows usually need.
type Customer struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// CheckoutSession is a hosted payment page. URL is where the customer pays.
type CheckoutSession struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	Status        string `json:"status"`
	PaymentStatus string `json:"payment_status"`
	AmountTotal   int64  `json:"amount_total"`
	Currency      string `json:"currency"`
}

// PaymentIntent is the state of a payment.
type PaymentIntent struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// Refund is the result of refunding a payment.
type Refund struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Amount int64  `json:"amount"`
}

// CustomerParams creates a customer.
type CustomerParams struct {
	Email string
	Name  string
}

// LineItem is one purchasable line on a checkout session (existing Price id).
type LineItem struct {
	Price    string
	Quantity int
}

// CheckoutParams creates a checkout session.
type CheckoutParams struct {
	Mode          string // "payment" (default), "subscription", or "setup"
	LineItems     []LineItem
	SuccessURL    string
	CancelURL     string
	CustomerEmail string
	Customer      string // existing customer id
}

// CreateCustomer creates a Stripe customer.
func (c *Client) CreateCustomer(ctx context.Context, p CustomerParams, idemKey string) (Customer, error) {
	form := url.Values{}
	if p.Email != "" {
		form.Set("email", p.Email)
	}
	if p.Name != "" {
		form.Set("name", p.Name)
	}
	var out Customer
	return out, c.post(ctx, "/customers", form, idemKey, &out)
}

// CreateCheckoutSession creates a hosted checkout session and returns its URL.
func (c *Client) CreateCheckoutSession(ctx context.Context, p CheckoutParams, idemKey string) (CheckoutSession, error) {
	if len(p.LineItems) == 0 {
		return CheckoutSession{}, fmt.Errorf("stripe: at least one line item is required")
	}
	mode := p.Mode
	if mode == "" {
		mode = "payment"
	}
	form := url.Values{}
	form.Set("mode", mode)
	if p.SuccessURL != "" {
		form.Set("success_url", p.SuccessURL)
	}
	if p.CancelURL != "" {
		form.Set("cancel_url", p.CancelURL)
	}
	if p.CustomerEmail != "" {
		form.Set("customer_email", p.CustomerEmail)
	}
	if p.Customer != "" {
		form.Set("customer", p.Customer)
	}
	for i, li := range p.LineItems {
		form.Set(fmt.Sprintf("line_items[%d][price]", i), li.Price)
		q := li.Quantity
		if q <= 0 {
			q = 1
		}
		form.Set(fmt.Sprintf("line_items[%d][quantity]", i), strconv.Itoa(q))
	}
	var out CheckoutSession
	return out, c.post(ctx, "/checkout/sessions", form, idemKey, &out)
}

// CreateRefund refunds a payment intent. amountCents == 0 refunds the full amount.
func (c *Client) CreateRefund(ctx context.Context, paymentIntentID string, amountCents int64, idemKey string) (Refund, error) {
	if paymentIntentID == "" {
		return Refund{}, fmt.Errorf("stripe: payment_intent id is required")
	}
	form := url.Values{}
	form.Set("payment_intent", paymentIntentID)
	if amountCents > 0 {
		form.Set("amount", strconv.FormatInt(amountCents, 10))
	}
	var out Refund
	return out, c.post(ctx, "/refunds", form, idemKey, &out)
}

// GetPaymentIntent fetches the current state of a payment intent.
func (c *Client) GetPaymentIntent(ctx context.Context, id string) (PaymentIntent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/payment_intents/"+url.PathEscape(id), nil)
	if err != nil {
		return PaymentIntent{}, err
	}
	var out PaymentIntent
	return out, c.do(req, &out)
}

func (c *Client) post(ctx context.Context, path string, form url.Values, idemKey string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	base, err := url.Parse(baseURL)
	if err != nil || base == nil || base.Scheme == "" || base.Host == "" {
		return errors.New("stripe: invalid API base URL")
	}
	hc := &ahttp.Client{Bearer: c.Key, CredentialOrigin: base.Scheme + "://" + base.Host}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain only a bounded amount before closing so a hostile error body
		// cannot consume unbounded memory or stall the worker indefinitely.
		_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
		return &APIError{Status: resp.StatusCode}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("stripe: decode: %w", err)
		}
	}
	return nil
}
