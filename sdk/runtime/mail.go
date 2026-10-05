package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/bright-interaction/reactor/sdk"
	"github.com/bright-interaction/reactor/sdk/email"
	"github.com/bright-interaction/reactor/sdk/wire"
)

type mailStepContextKey struct{}
type mailStepIdentity struct {
	name           string
	seq            int64
	attempt        int
	idempotencyKey string
}

// MailSend asks the host to send one structured message using a connection
// reference. The host alone selects the provider endpoint and attaches OAuth.
func (p *PipeFlow) MailSend(ctx context.Context, credentialID string, msg email.Message) (string, error) {
	if !p.mailBroker.Load() {
		return "", email.ErrMailBrokerUnavailable
	}
	if ctx == nil {
		return "", errors.New("email: context is required")
	}
	step, ok := ctx.Value(mailStepContextKey{}).(mailStepIdentity)
	if !ok || step.name == "" || step.seq < 1 || step.attempt < 1 || step.idempotencyKey == "" {
		return "", reactor.Permanent(errors.New("email: connected send requires a durable Step with an idempotency key"))
	}
	id := p.id()
	frame, err := wire.Wrap(id, 0, wire.KindMailSendRequest, wire.MailSendRequest{
		CredentialID: credentialID,
		StepName:     step.name, StepSeq: step.seq, StepAttempt: step.attempt, IdempotencyKey: step.idempotencyKey,
		Message: wire.MailMessage{
			From: msg.From, To: msg.To, Cc: msg.Cc, Subject: msg.Subject,
			Text: msg.Text, HTML: msg.HTML,
		},
	})
	if err != nil {
		return "", err
	}
	replyCh := p.expect(id)
	if err := p.write(frame); err != nil {
		p.unexpect(id)
		return "", err
	}
	var reply wire.Frame
	select {
	case <-ctx.Done():
		p.unexpect(id)
		return "", ctx.Err()
	case value, ok := <-replyCh:
		if !ok {
			return "", ErrPipeClosed
		}
		reply = value
	}
	if reply.Kind != wire.KindMailSendReply {
		return "", fmt.Errorf("email: unexpected host reply kind %q", reply.Kind)
	}
	var body wire.MailSendReply
	if err := wire.Unwrap(reply, &body); err != nil {
		return "", errors.New("email: invalid host mail reply")
	}
	if body.ErrorCode != "" {
		brokerErr := &email.BrokerError{Code: body.ErrorCode, Status: body.Status}
		if body.ErrorCode == "ambiguous" {
			return "", reactor.Permanent(brokerErr)
		}
		return "", brokerErr
	}
	if body.Status < 200 || body.Status >= 300 {
		return "", errors.New("email: invalid host mail status")
	}
	return body.MessageID, nil
}
