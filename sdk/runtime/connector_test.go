package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	reactorhttp "github.com/bright-interaction/reactor/sdk/http"
	"github.com/bright-interaction/reactor/sdk/wire"
)

func TestConnectorRequestRequiresAdvertisedHostBroker(t *testing.T) {
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
	if _, err := p.ConnectorRequest(context.Background(), "oauth:conn-1", "GET", "/data"); !errors.Is(err, reactorhttp.ErrConnectorUnavailable) {
		t.Fatalf("old host connector request = %v, want unavailable before frame", err)
	}
	if childOutput.Len() != 0 {
		t.Fatalf("old host received %d connector frame bytes", childOutput.Len())
	}
}

func TestConnectorRequestWireCarriesNoTokenOrOrigin(t *testing.T) {
	hostToChildR, hostToChildW := io.Pipe()
	childToHostR, childToHostW := io.Pipe()
	defer hostToChildR.Close()
	defer hostToChildW.Close()
	defer childToHostR.Close()
	defer childToHostW.Close()
	p := New(hostToChildR, childToHostW, nil)
	defer p.Done()
	hostEncoder := wire.NewEncoder(hostToChildW)
	hostDecoder := wire.NewDecoder(childToHostR)
	hello, err := wire.Wrap(1, 0, wire.KindHello, wire.Hello{Version: wire.Version, RunID: "run-test", ConnectorBroker: true})
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
	type outcome struct {
		response reactorhttp.ConnectorResponse
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := p.ConnectorRequest(ctx, "oauth:conn-1", "GET", "/services/data/v60.0/query")
		done <- outcome{response: response, err: err}
	}()
	frame, err := hostDecoder.Decode()
	if err != nil || frame.Kind != wire.KindConnectorRequest {
		t.Fatalf("connector frame = %+v, %v", frame, err)
	}
	var request wire.ConnectorRequest
	if err := wire.Unwrap(frame, &request); err != nil {
		t.Fatal(err)
	}
	if request.CredentialID != "oauth:conn-1" || request.Method != "GET" || request.Path != "/services/data/v60.0/query" {
		t.Fatalf("connector request = %+v", request)
	}
	reply, err := wire.Wrap(2, frame.ID, wire.KindConnectorReply, wire.ConnectorReply{Status: 200, Body: []byte(`{"ok":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := hostEncoder.Encode(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.response.Status != 200 || string(result.response.Body) != `{"ok":true}` {
			t.Fatalf("connector response = %+v, %v", result.response, result.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// A reply for a different request ID cannot satisfy this request. The
	// caller times out and no provider result is delivered to the wrong Step.
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer shortCancel()
	go func() {
		response, err := p.ConnectorRequest(shortCtx, "oauth:conn-1", "GET", "/services/data/v60.0/limits")
		done <- outcome{response: response, err: err}
	}()
	secondFrame, err := hostDecoder.Decode()
	if err != nil {
		t.Fatal(err)
	}
	wrongReply, err := wire.Wrap(3, secondFrame.ID+1000, wire.KindConnectorReply, wire.ConnectorReply{Status: 200, Body: []byte(`{"wrong":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := hostEncoder.Encode(wrongReply); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if !errors.Is(result.err, context.DeadlineExceeded) || result.response.Status != 0 {
			t.Fatalf("mismatched reply delivered %+v, %v", result.response, result.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
