package runtime

import (
	"context"
	"fmt"

	reactorhttp "github.com/bright-interaction/reactor/sdk/http"
	"github.com/bright-interaction/reactor/sdk/wire"
)

// ConnectorRequest asks the host to make one credential-aware HTTP attempt.
// The child sends only a credential reference and relative path. The host
// validates the run/tenant/grant and attaches the live token itself.
func (p *PipeFlow) ConnectorRequest(ctx context.Context, credentialID, method, path string) (reactorhttp.ConnectorResponse, error) {
	var empty reactorhttp.ConnectorResponse
	if !p.connectorBroker.Load() {
		return empty, reactorhttp.ErrConnectorUnavailable
	}
	id := p.id()
	frame, err := wire.Wrap(id, 0, wire.KindConnectorRequest, wire.ConnectorRequest{
		CredentialID: credentialID, Method: method, Path: path,
	})
	if err != nil {
		return empty, err
	}
	replyCh := p.expect(id)
	if err := p.write(frame); err != nil {
		p.unexpect(id)
		return empty, err
	}
	var reply wire.Frame
	select {
	case <-ctx.Done():
		p.unexpect(id)
		return empty, ctx.Err()
	case value, ok := <-replyCh:
		if !ok {
			return empty, ErrPipeClosed
		}
		reply = value
	}
	if reply.Kind != wire.KindConnectorReply {
		return empty, fmt.Errorf("connector broker: unexpected reply kind %q", reply.Kind)
	}
	var body wire.ConnectorReply
	if err := wire.Unwrap(reply, &body); err != nil {
		return empty, fmt.Errorf("connector broker: decode reply: %w", err)
	}
	return reactorhttp.ConnectorResponse{
		Status: body.Status, Body: body.Body,
		RetryAfterMs: body.RetryAfterMs, ErrorCode: body.ErrorCode,
	}, nil
}
