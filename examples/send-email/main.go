// send-email is the smallest workflow that sends through a connected account.
// It takes a webhook payload naming a Google connection (connected once on the
// Connections page) plus the message, and asks the host to send it via the
// Gmail API. The workflow never receives the account token.
//
// Build:    reactor workflow build --src examples/send-email --slug send-email
// Register: reactor workflow register --db ... --slug send-email
// Trigger:  POST /webhook/<token> with
//
//	{"event_id":"evt_123","connection_id":"conn_x","from":"me@x.com","to":"c@y.com",
//	 "subject":"Hi","body":"hello"}
package main

import (
	"context"
	"errors"
	"time"

	"github.com/bright-interaction/reactor/sdk"
	"github.com/bright-interaction/reactor/sdk/email"
	"github.com/bright-interaction/reactor/sdk/runtime"
)

//nolint:gochecknoglobals // SDK contract: package-level declarations.
var (
	Workflow = reactor.Workflow{Slug: "send-email", Version: "0.1.0"}
	Trigger  = reactor.WebhookTrigger{Path: "/webhook/send-email", Provider: "generic"}
)

// Payload is the webhook body. ConnectionID points at a Google account
// connected on the Connections page. EventID is stable for this run's replay;
// repeated webhook deliveries are separate runs unless ingress deduplicates them.
type Payload struct {
	EventID      string `json:"event_id"`
	ConnectionID string `json:"connection_id"`
	From         string `json:"from"`
	To           string `json:"to"`
	Subject      string `json:"subject"`
	Body         string `json:"body"`
}

// Sent is the step output: the Gmail message id, journaled for replay after
// successful completion. An unconfirmed send needs provider reconciliation
// before an operator starts a new run for the same upstream event.
type Sent struct {
	MessageID string `json:"message_id"`
}

func Run(ctx context.Context, flow reactor.Flow, in Payload) error {
	log := flow.Logger()
	log.Info("send-email: starting")
	if in.EventID == "" || in.ConnectionID == "" || in.To == "" {
		return reactor.Permanent(errors.New("send-email: event_id, connection_id, and to are required"))
	}

	_, err := reactor.Step(flow, ctx, "send", reactor.StepOpts{
		// The same upstream event keeps its Step identity across a run replay.
		IdempotencyKey: "send-email:" + in.EventID,
		Timeout:        30 * time.Second,
	}, func(ctx context.Context) (Sent, error) {
		id, err := email.SendConnected(ctx, "oauth:"+in.ConnectionID, email.Message{
			From:    in.From,
			To:      []string{in.To},
			Subject: in.Subject,
			Text:    in.Body,
		})
		if err != nil {
			return Sent{}, err
		}
		return Sent{MessageID: id}, nil
	})
	return err
}

func main() {
	runtime.Serve(Workflow, Trigger, Run)
}
