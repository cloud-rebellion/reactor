package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/sdk"
	"github.com/bright-interaction/reactor/sdk/email"
	"github.com/bright-interaction/reactor/sdk/wire"
)

func TestMailSendRequiresAdvertisedHostBroker(t *testing.T) {
	hostToChildR, hostToChildW := io.Pipe()
	defer hostToChildR.Close()
	defer hostToChildW.Close()
	var childOutput bytes.Buffer
	p := New(hostToChildR, &childOutput, nil)
	defer p.Done()
	hello, err := wire.Wrap(1, 0, wire.KindHello, wire.Hello{Version: wire.Version, RunID: "run-old-host"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.NewEncoder(hostToChildW).Encode(hello); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.WaitHello(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = p.MailSend(ctx, "oauth:conn-1", email.Message{From: "a@example.test", To: []string{"b@example.test"}, Text: "hello"})
	if !errors.Is(err, email.ErrMailBrokerUnavailable) || childOutput.Len() != 0 {
		t.Fatalf("old host mail call = %v; sent %d frame bytes", err, childOutput.Len())
	}
}

func TestMailSendWireCarriesStructuredMessageWithoutTokenOrOrigin(t *testing.T) {
	hostToChildR, hostToChildW := io.Pipe()
	childToHostR, childToHostW := io.Pipe()
	defer hostToChildR.Close()
	defer hostToChildW.Close()
	defer childToHostR.Close()
	defer childToHostW.Close()
	p := New(hostToChildR, childToHostW, nil)
	defer p.Done()
	hostEncoder := wire.NewEncoder(hostToChildW)
	hello, err := wire.Wrap(1, 0, wire.KindHello, wire.Hello{Version: wire.Version, RunID: "run-mail", MailBroker: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := hostEncoder.Encode(hello); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.WaitHello(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.MailSend(ctx, "oauth:conn-1", email.Message{From: "a@example.test", To: []string{"b@example.test"}, Text: "hello"}); !reactor.IsPermanent(err) {
		t.Fatalf("mail send outside Step should fail permanently: %v", err)
	}
	ctx = context.WithValue(ctx, mailStepContextKey{}, mailStepIdentity{
		name: "send", seq: 7, attempt: 2, idempotencyKey: "mail-once",
	})
	type outcome struct {
		id  string
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		id, err := p.MailSend(ctx, "oauth:conn-1", email.Message{From: "a@example.test", To: []string{"b@example.test"}, Text: "hello"})
		done <- outcome{id, err}
	}()
	frame, err := wire.NewDecoder(childToHostR).Decode()
	if err != nil || frame.Kind != wire.KindMailSendRequest {
		t.Fatalf("mail frame = %+v, %v", frame, err)
	}
	var request wire.MailSendRequest
	if err := wire.Unwrap(frame, &request); err != nil {
		t.Fatal(err)
	}
	if request.CredentialID != "oauth:conn-1" || request.Message.Text != "hello" ||
		request.StepName != "send" || request.StepSeq != 7 || request.StepAttempt != 2 || request.IdempotencyKey != "mail-once" ||
		strings.Contains(string(frame.Body), "Bearer ") || strings.Contains(string(frame.Body), "https://") {
		t.Fatalf("unsafe mail request: %+v", request)
	}
	reply, err := wire.Wrap(2, frame.ID, wire.KindMailSendReply, wire.MailSendReply{Status: 200, MessageID: "msg_123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := hostEncoder.Encode(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.id != "msg_123" {
			t.Fatalf("mail result = %+v", result)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		_, err := p.MailSend(ctx, "oauth:conn-1", email.Message{From: "a@example.test", To: []string{"b@example.test"}, Text: "hello"})
		done <- outcome{"", err}
	}()
	frame, err = wire.NewDecoder(childToHostR).Decode()
	if err != nil || frame.Kind != wire.KindMailSendRequest {
		t.Fatalf("second mail frame = %+v, %v", frame, err)
	}
	reply, err = wire.Wrap(3, frame.ID, wire.KindMailSendReply, wire.MailSendReply{ErrorCode: "ambiguous"})
	if err != nil {
		t.Fatal(err)
	}
	if err := hostEncoder.Encode(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		var brokerErr *email.BrokerError
		if !reactor.IsPermanent(result.err) || !errors.As(result.err, &brokerErr) || brokerErr.Code != "ambiguous" ||
			!strings.Contains(result.err.Error(), "reconcile with provider") {
			t.Fatalf("ambiguous send should require manual reconciliation: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
