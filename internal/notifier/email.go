package notifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/safehttp"
)

// EmailSender delivers via SMTP. Config shape:
//
//	{
//	  "host": "smtp.example.com",
//	  "port": 587,
//	  "username": "alerts@example.com",
//	  "password": "...",          // plaintext (operator-managed)
//	  "from": "alerts@example.com",
//	  "to": "ops@example.com",
//	  "starttls": true            // optional, default true on port 587
//	}
//
// STARTTLS is the default for port 587 and required when selected;
// port 465 uses implicit TLS. Plain port 25 is also supported. Username/password are passed via
// PLAIN auth so any standards-compliant SMTP server works.
//
// Reactor resolves password_credential_id from the vault immediately before
// delivery; the plaintext password form remains for legacy operator-managed
// channels, while MCP-created channels require the credential reference.
type EmailSender struct {
	// dial is the test seam; nil means use the default net dialer.
	dial func(network, addr string, timeout time.Duration) (net.Conn, error)
	// tlsRoots is a test seam for local SMTP certificates; nil uses system roots.
	tlsRoots *x509.CertPool
}

// NewEmailSender returns a sender backed by the stdlib net/smtp client.
func NewEmailSender() *EmailSender {
	return &EmailSender{}
}

// Kind implements Sender.
func (s *EmailSender) Kind() string { return "email_smtp" }

// Send delivers one message. Returns the SMTP server's error message
// verbatim on auth or recipient failure so the operator can debug
// from the dashboard log line.
func (s *EmailSender) Send(ctx context.Context, cfg json.RawMessage, ev Event) error {
	var c struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		From     string `json:"from"`
		To       string `json:"to"`
		StartTLS *bool  `json:"starttls"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return fmt.Errorf("email: parse config: %w", err)
	}
	if c.Host == "" || c.From == "" || c.To == "" {
		return fmt.Errorf("email: host, from, to are required")
	}
	if c.Port == 0 {
		c.Port = 587
	}
	if c.Port == 465 && c.StartTLS != nil && *c.StartTLS {
		return fmt.Errorf("email: port 465 uses implicit TLS; do not request STARTTLS")
	}
	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))

	dialer := s.dial
	if dialer == nil {
		dialer = func(network, addr string, timeout time.Duration) (net.Conn, error) {
			allowPrivate := os.Getenv("REACTOR_SMTP_ALLOW_PRIVATE") == "1"
			return safehttp.DialContext(ctx, network, addr, allowPrivate)
		}
	}

	deadline, ok := ctx.Deadline()
	timeout := 10 * time.Second
	if ok {
		if rem := time.Until(deadline); rem > 0 {
			timeout = rem
		}
	}

	conn, err := dialer("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("email: dial %s: %w", addr, err)
	}
	defer conn.Close()
	// Bound the WHOLE SMTP exchange, not just the dial. Without a
	// connection deadline a server that accepts TCP then stalls (e.g. a
	// slowloris) would block NewClient/STARTTLS/Auth/Data forever and
	// hang the dispatcher's graceful Drain. SetDeadline covers every
	// subsequent read+write on this conn.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, RootCAs: s.tlsRoots}
	if c.Port == 465 {
		secureConn := tls.Client(conn, tlsCfg)
		if err := secureConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("email: implicit TLS: %w", err)
		}
		conn = secureConn
	}

	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return fmt.Errorf("email: smtp.NewClient: %w", err)
	}
	defer client.Quit()

	wantSTARTTLS := c.Port == 587
	if c.StartTLS != nil {
		wantSTARTTLS = *c.StartTLS
	}
	if wantSTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("email: STARTTLS required but SMTP server did not advertise it")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("email: STARTTLS: %w", err)
		}
	}
	if c.Username != "" {
		auth := smtp.PlainAuth("", c.Username, c.Password, c.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email: auth: %w", err)
		}
	}
	if err := client.Mail(c.From); err != nil {
		return fmt.Errorf("email: MAIL FROM: %w", err)
	}
	for _, rcpt := range splitRecipients(c.To) {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("email: RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email: DATA: %w", err)
	}
	if _, err := w.Write([]byte(emailMessage(c.From, c.To, ev))); err != nil {
		w.Close()
		return fmt.Errorf("email: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: close body: %w", err)
	}
	return nil
}

func splitRecipients(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func emailMessage(from, to string, ev Event) string {
	subject := alertHeadline(ev)
	body := alertPlainText(ev)
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}
