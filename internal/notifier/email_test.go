package notifier

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEmailSenderRequiresAdvertisedSTARTTLSBeforeCredentialsOrMail(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(serverConn)
		if _, err := io.WriteString(serverConn, "220 localhost ESMTP\r\n"); err != nil {
			serverDone <- err
			return
		}
		if err := expectSMTPCommand(reader, "EHLO "); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.WriteString(serverConn, "250 localhost\r\n"); err != nil {
			serverDone <- err
			return
		}
		// A required STARTTLS extension is absent. The only next command may
		// be QUIT; in particular AUTH, MAIL, and DATA must never reach the peer.
		if err := expectSMTPCommand(reader, "QUIT"); err != nil {
			serverDone <- err
			return
		}
		_, err := io.WriteString(serverConn, "221 goodbye\r\n")
		serverDone <- err
	}()
	sender := &EmailSender{dial: func(_, _ string, _ time.Duration) (net.Conn, error) { return clientConn, nil }}
	err := sender.Send(context.Background(), json.RawMessage(`{"host":"localhost","port":587,"username":"alerts","password":"secret","from":"alerts@example.com","to":"ops@example.com"}`), Event{RunID: "run-starttls", Status: "failed"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS required") {
		t.Fatalf("send without advertised STARTTLS = %v; want refusal", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestEmailSenderPort465UsesVerifiedImplicitTLS(t *testing.T) {
	cert, roots := localSMTPCertificate(t)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))
		secure := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if err := secure.Handshake(); err != nil {
			serverDone <- fmt.Errorf("server TLS handshake: %w", err)
			return
		}
		reader := bufio.NewReader(secure)
		if _, err := io.WriteString(secure, "220 localhost ESMTP\r\n"); err != nil {
			serverDone <- err
			return
		}
		if err := expectSMTPCommand(reader, "EHLO "); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.WriteString(secure, "250-localhost\r\n250 AUTH PLAIN\r\n"); err != nil {
			serverDone <- err
			return
		}
		authLine, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(authLine, "AUTH PLAIN ") {
			serverDone <- fmt.Errorf("auth command = %q, %v", authLine, err)
			return
		}
		encoded := strings.TrimSpace(strings.TrimPrefix(authLine, "AUTH PLAIN "))
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || string(decoded) != "\x00alerts\x00secret" {
			serverDone <- fmt.Errorf("unexpected PLAIN auth payload: %v", err)
			return
		}
		if _, err := io.WriteString(secure, "235 authenticated\r\n"); err != nil {
			serverDone <- err
			return
		}
		for _, command := range []string{"MAIL FROM:<alerts@example.com>", "RCPT TO:<ops@example.com>"} {
			if err := expectSMTPCommand(reader, command); err != nil {
				serverDone <- err
				return
			}
			if _, err := io.WriteString(secure, "250 OK\r\n"); err != nil {
				serverDone <- err
				return
			}
		}
		if err := expectSMTPCommand(reader, "DATA"); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.WriteString(secure, "354 send message\r\n"); err != nil {
			serverDone <- err
			return
		}
		var message strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == ".\r\n" {
				break
			}
			message.WriteString(line)
		}
		if !strings.Contains(message.String(), "run-implicit-tls") {
			serverDone <- fmt.Errorf("SMTP message omitted run id")
			return
		}
		if strings.Contains(message.String(), "credential-canary") {
			serverDone <- fmt.Errorf("raw step error escaped in SMTP DATA")
			return
		}
		if _, err := io.WriteString(secure, "250 queued\r\n"); err != nil {
			serverDone <- err
			return
		}
		if err := expectSMTPCommand(reader, "QUIT"); err != nil {
			serverDone <- err
			return
		}
		_, err = io.WriteString(secure, "221 goodbye\r\n")
		_ = serverConn.Close()
		serverDone <- err
	}()
	sender := &EmailSender{
		dial:     func(_, _ string, _ time.Duration) (net.Conn, error) { return clientConn, nil },
		tlsRoots: roots,
	}
	err := sender.Send(context.Background(), json.RawMessage(`{"host":"localhost","port":465,"username":"alerts","password":"secret","from":"alerts@example.com","to":"ops@example.com"}`), Event{RunID: "run-implicit-tls", Status: "failed", ErrorText: "credential-canary"})
	if err != nil {
		t.Fatalf("implicit TLS send: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestEmailSenderPort465RejectsConflictingSTARTTLS(t *testing.T) {
	sender := &EmailSender{dial: func(_, _ string, _ time.Duration) (net.Conn, error) {
		t.Fatal("invalid TLS mode reached the dialer")
		return nil, nil
	}}
	err := sender.Send(context.Background(), json.RawMessage(`{"host":"localhost","port":465,"from":"alerts@example.com","to":"ops@example.com","starttls":true}`), Event{})
	if err == nil || !strings.Contains(err.Error(), "implicit TLS") {
		t.Fatalf("conflicting port 465 config = %v; want refusal", err)
	}
}

func expectSMTPCommand(reader *bufio.Reader, prefix string) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("SMTP command = %q, want prefix %q", line, prefix)
	}
	return nil
}

func localSMTPCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
