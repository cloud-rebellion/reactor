// Package email is the workflow-side email connector. Connected Google and
// Microsoft accounts use SendConnected inside a durable Step closure:
//
//	id, err := email.SendConnected(ctx, "oauth:"+connectionID, email.Message{
//		From: "me@example.com", To: []string{"customer@acme.com"},
//		Subject: "Welcome", Text: "Thanks for signing up.",
//	})
//
// The host fixes the provider endpoint and attaches the token without
// releasing it to workflow code. Use one send and no other side effects per
// Step, with a nonempty IdempotencyKey. An uncertain provider outcome requires
// manual reconciliation.
package email

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/url"
	"strings"
	"sync/atomic"

	ahttp "github.com/bright-interaction/reactor/sdk/http"
)

// Endpoints are package vars so tests can point them at a fake server. They
// default to the real Gmail + Microsoft Graph send endpoints.
var (
	gmailSendURL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
	graphSendURL = "https://graph.microsoft.com/v1.0/me/sendMail"
)

// Provider identifies which mail backend a connection talks to. It matches the
// OAuth provider id of the connection.
type Provider string

const (
	Google    Provider = "google"
	Microsoft Provider = "microsoft"
)

// Message is a plain-text and/or HTML email. Set Text, HTML, or both (both
// sends a multipart/alternative so clients pick the richest they render).
type Message struct {
	From    string   // sender address, usually the connected account
	To      []string // at least one recipient
	Cc      []string
	Subject string
	Text    string // plain-text body
	HTML    string // optional HTML body
}

// ErrMailBrokerUnavailable means the workflow host does not support
// token-free connected-account sends. There is no raw-token fallback.
var ErrMailBrokerUnavailable = errors.New("email: host mail broker is unavailable")

// MailSenderFunc is bound by sdk/runtime after the host advertises its mail
// broker. The credential reference and structured message cross the pipe;
// the OAuth token and provider URL stay on the host.
type MailSenderFunc func(context.Context, string, Message) (string, error)

type mailSenderBinding struct{ send MailSenderFunc }

var mailSender atomic.Pointer[mailSenderBinding]

// BrokerError contains only a stable host refusal code and HTTP status. It
// never includes a provider response body, URL, recipient, or token.
type BrokerError struct {
	Code   string
	Status int
}

func (e *BrokerError) Error() string {
	if e == nil {
		return "email: host mail broker refused request"
	}
	code := e.Code
	if code == "" || len(code) > 64 || strings.IndexFunc(code, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) >= 0 {
		code = "broker_failure"
	}
	if code == "ambiguous" {
		return "email: mail send outcome uncertain; reconcile with provider before redrive"
	}
	return "email: host mail broker refused request: " + code
}

func BindMailSender(send MailSenderFunc) func() {
	var binding *mailSenderBinding
	if send != nil {
		binding = &mailSenderBinding{send: send}
	}
	previous := mailSender.Swap(binding)
	return func() { mailSender.Store(previous) }
}

// SendConnected sends through a tenant-owned Google or Microsoft connection
// without exposing its access token to workflow code. Gmail returns the
// provider message ID; Microsoft Graph returns an empty ID on HTTP 202.
// Place one send inside a durable Step with an idempotency key and no other
// side effects. The host does not retry an ambiguous provider POST.
func SendConnected(ctx context.Context, credentialID string, msg Message) (string, error) {
	if ahttp.IsDryRun() {
		return "", ahttp.ErrDryRun
	}
	if ctx == nil {
		return "", errors.New("email: context is required")
	}
	if !strings.HasPrefix(credentialID, "oauth:") || len(credentialID) <= len("oauth:") || len(credentialID) > 256 ||
		strings.IndexFunc(credentialID, func(r rune) bool { return r < 0x21 || r == 0x7f }) >= 0 {
		return "", errors.New("email: invalid connected-account reference")
	}
	if err := msg.Validate(); err != nil {
		return "", err
	}
	binding := mailSender.Load()
	if binding == nil || binding.send == nil {
		return "", ErrMailBrokerUnavailable
	}
	return binding.send(ctx, credentialID, msg)
}

// Validate checks the fields shared by the Gmail and Microsoft adapters.
func (m Message) Validate() error {
	if m.From == "" || len(m.To) == 0 || (m.Text == "" && m.HTML == "") {
		return errors.New("email: From, To, and Text or HTML are required")
	}
	return m.validateHeaders()
}

// GmailPayload and OutlookPayload are also used by the host broker so both
// sending paths encode the same validated message shape.
func (m Message) GmailPayload() ([]byte, error) { return m.rfc822() }
func (m Message) OutlookPayload() (map[string]any, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return graphPayload(m), nil
}

// Send dispatches to the right provider. It is the convenience entry point when
// the workflow already knows the connection's provider; otherwise call
// SendGmail / SendOutlook directly. Returns the provider message id when one is
// available (Gmail returns an id; Microsoft Graph does not).
func Send(ctx context.Context, provider Provider, accessToken string, msg Message) (string, error) {
	switch provider {
	case Google:
		return SendGmail(ctx, accessToken, msg)
	case Microsoft:
		return "", SendOutlook(ctx, accessToken, msg)
	default:
		return "", fmt.Errorf("email: unsupported provider %q (want google or microsoft)", provider)
	}
}

// SendGmail sends msg via the Gmail API using a Google OAuth access token
// (scope gmail.send). Returns the sent message id.
func SendGmail(ctx context.Context, accessToken string, msg Message) (string, error) {
	if accessToken == "" {
		return "", errors.New("email: empty access token")
	}
	raw, err := msg.rfc822()
	if err != nil {
		return "", err
	}
	c, err := credentialClient(accessToken, gmailSendURL)
	if err != nil {
		return "", err
	}
	body := map[string]string{"raw": base64.URLEncoding.EncodeToString(raw)}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.PostJSON(ctx, gmailSendURL, body, &out); err != nil {
		return "", fmt.Errorf("email: gmail send: %w", err)
	}
	return out.ID, nil
}

// SendOutlook sends msg via Microsoft Graph using a Microsoft OAuth access
// token (scope Mail.Send). Graph returns 202 with no body, so there is no id.
func SendOutlook(ctx context.Context, accessToken string, msg Message) error {
	if accessToken == "" {
		return errors.New("email: empty access token")
	}
	if msg.From == "" || len(msg.To) == 0 {
		return errors.New("email: From and at least one To are required")
	}
	if err := msg.validateHeaders(); err != nil {
		return err
	}
	c, err := credentialClient(accessToken, graphSendURL)
	if err != nil {
		return err
	}
	if err := c.PostJSON(ctx, graphSendURL, graphPayload(msg), nil); err != nil {
		return fmt.Errorf("email: outlook send: %w", err)
	}
	return nil
}

func credentialClient(token, endpoint string) (*ahttp.Client, error) {
	base, err := url.Parse(endpoint)
	if err != nil || base == nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("email: invalid provider endpoint")
	}
	return &ahttp.Client{Bearer: token, CredentialOrigin: base.Scheme + "://" + base.Host}, nil
}

// graphPayload builds the Microsoft Graph sendMail JSON body.
func graphPayload(m Message) map[string]any {
	ct, content := "Text", m.Text
	if m.HTML != "" {
		ct, content = "HTML", m.HTML
	}
	msg := map[string]any{
		"subject":      m.Subject,
		"body":         map[string]string{"contentType": ct, "content": content},
		"toRecipients": recipients(m.To),
	}
	if len(m.Cc) > 0 {
		msg["ccRecipients"] = recipients(m.Cc)
	}
	if m.From != "" {
		msg["from"] = map[string]any{"emailAddress": map[string]string{"address": m.From}}
	}
	return map[string]any{"message": msg, "saveToSentItems": true}
}

func recipients(addrs []string) []map[string]any {
	out := make([]map[string]any, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, map[string]any{"emailAddress": map[string]string{"address": a}})
	}
	return out
}

// rfc822 builds an RFC 2822 message (CRLF line endings, UTF-8 quoted-printable
// bodies) suitable for Gmail's raw send.
func (m Message) rfc822() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", m.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(m.To, ", "))
	if len(m.Cc) > 0 {
		fmt.Fprintf(&b, "Cc: %s\r\n", strings.Join(m.Cc, ", "))
	}
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	b.WriteString("MIME-Version: 1.0\r\n")

	switch {
	case m.Text != "" && m.HTML != "":
		boundary := m.boundary()
		fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		writePart(&b, boundary, "text/plain", m.Text)
		writePart(&b, boundary, "text/html", m.HTML)
		fmt.Fprintf(&b, "--%s--\r\n", boundary)
	case m.HTML != "":
		b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		writeQP(&b, m.HTML)
	default:
		b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		writeQP(&b, m.Text)
	}
	return b.Bytes(), nil
}

// validateHeaders rejects line breaks and NULs in values that are serialized
// into RFC 822 headers or mirrored into provider recipient fields. Without
// this check an address such as "victim@example.com\r\nBcc: attacker@evil"
// can add a recipient header to a Gmail raw message.
func (m Message) validateHeaders() error {
	check := func(name, value string) error {
		if strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("email: %s contains forbidden header control characters", name)
		}
		return nil
	}
	if err := check("From", m.From); err != nil {
		return err
	}
	if err := check("Subject", m.Subject); err != nil {
		return err
	}
	for _, addr := range m.To {
		if err := check("To", addr); err != nil {
			return err
		}
	}
	for _, addr := range m.Cc {
		if err := check("Cc", addr); err != nil {
			return err
		}
	}
	return nil
}

func writePart(b *bytes.Buffer, boundary, contentType, content string) {
	fmt.Fprintf(b, "--%s\r\n", boundary)
	fmt.Fprintf(b, "Content-Type: %s; charset=\"UTF-8\"\r\n", contentType)
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	writeQP(b, content)
	b.WriteString("\r\n")
}

func writeQP(b *bytes.Buffer, s string) {
	w := quotedprintable.NewWriter(b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
}

// boundary derives a deterministic MIME boundary from the content so the same
// message always serialises identically (helpful for replay) while never
// colliding with the body text in practice.
func (m Message) boundary() string {
	sum := sha256.Sum256([]byte(m.Text + "\x00" + m.HTML))
	return "reactor_" + hex.EncodeToString(sum[:])[:32]
}
