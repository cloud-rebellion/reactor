// Package mollie is the workflow-side Mollie connector (EU payments). AI-
// generated workflows call it from inside a Step closure to create payments and
// refunds. The API key lives in the vault and is fetched at run time:
//
//	c := &mollie.Client{Key: string(vault.MustGet("mollie-key").Reveal())}
//	pay, err := c.CreatePayment(ctx, mollie.PaymentParams{
//		Amount:      mollie.Amount{Currency: "EUR", Value: "10.00"},
//		Description: "Order 12345",
//		RedirectURL: "https://x/return",
//	})
//	// redirect the customer to pay.CheckoutURL
//
// Mollie speaks JSON. Creating a payment is a side effect, so wrap the call in a
// Step with a deterministic IdempotencyKey.
package mollie

import (
	"context"
	"fmt"
	"net/url"

	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

// baseURL is package-owned so workflow input cannot redirect a Mollie key to
// another origin. Tests in this package can point it at a fake server.
var baseURL = "https://api.mollie.com/v2"

// Client holds the Mollie API key (test_... or live_...).
type Client struct {
	Key string
}

// Amount is a Mollie monetary amount. Value is a decimal string, e.g. "10.00".
type Amount struct {
	Currency string `json:"currency"`
	Value    string `json:"value"`
}

// Payment is a Mollie payment. CheckoutURL is where the customer pays.
type Payment struct {
	ID          string
	Status      string
	CheckoutURL string
}

// Refund is the result of refunding a payment.
type Refund struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// PaymentParams creates a payment.
type PaymentParams struct {
	Amount      Amount
	Description string
	RedirectURL string
	WebhookURL  string // optional; Mollie POSTs status updates here
}

// rawPayment matches the Mollie payment response, including the nested links.
type rawPayment struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Links  struct {
		Checkout struct {
			Href string `json:"href"`
		} `json:"checkout"`
	} `json:"_links"`
}

func (r rawPayment) toPayment() Payment {
	return Payment{ID: r.ID, Status: r.Status, CheckoutURL: r.Links.Checkout.Href}
}

// CreatePayment creates a payment and returns its id, status, and checkout URL.
func (c *Client) CreatePayment(ctx context.Context, p PaymentParams) (Payment, error) {
	if p.Amount.Currency == "" || p.Amount.Value == "" {
		return Payment{}, fmt.Errorf("mollie: amount currency and value are required")
	}
	if p.Description == "" || p.RedirectURL == "" {
		return Payment{}, fmt.Errorf("mollie: description and redirectUrl are required")
	}
	body := map[string]any{
		"amount":      p.Amount,
		"description": p.Description,
		"redirectUrl": p.RedirectURL,
	}
	if p.WebhookURL != "" {
		body["webhookUrl"] = p.WebhookURL
	}
	var raw rawPayment
	hc, err := credentialClient(c.Key)
	if err != nil {
		return Payment{}, err
	}
	if err := hc.PostJSON(ctx, baseURL+"/payments", body, &raw); err != nil {
		return Payment{}, fmt.Errorf("mollie: create payment: %w", err)
	}
	return raw.toPayment(), nil
}

// GetPayment fetches the current state of a payment (poll its Status).
func (c *Client) GetPayment(ctx context.Context, id string) (Payment, error) {
	if id == "" {
		return Payment{}, fmt.Errorf("mollie: payment id is required")
	}
	var raw rawPayment
	hc, err := credentialClient(c.Key)
	if err != nil {
		return Payment{}, err
	}
	if err := hc.Get(ctx, baseURL+"/payments/"+id, &raw); err != nil {
		return Payment{}, fmt.Errorf("mollie: get payment: %w", err)
	}
	return raw.toPayment(), nil
}

// CreateRefund refunds a payment (full or partial via amount).
func (c *Client) CreateRefund(ctx context.Context, paymentID string, amount Amount) (Refund, error) {
	if paymentID == "" {
		return Refund{}, fmt.Errorf("mollie: payment id is required")
	}
	body := map[string]any{}
	if amount.Currency != "" && amount.Value != "" {
		body["amount"] = amount
	}
	var out Refund
	hc, err := credentialClient(c.Key)
	if err != nil {
		return Refund{}, err
	}
	if err := hc.PostJSON(ctx, baseURL+"/payments/"+paymentID+"/refunds", body, &out); err != nil {
		return Refund{}, fmt.Errorf("mollie: create refund: %w", err)
	}
	return out, nil
}

func credentialClient(key string) (*ahttp.Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base == nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("mollie: invalid API base URL")
	}
	return &ahttp.Client{Bearer: key, CredentialOrigin: base.Scheme + "://" + base.Host}, nil
}
