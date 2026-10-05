package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bright-interaction/reactor/sdk"
	reactoremail "github.com/bright-interaction/reactor/sdk/email"
	reactorhttp "github.com/bright-interaction/reactor/sdk/http"
	"github.com/bright-interaction/reactor/sdk/vault"
)

// Serve is the entrypoint AI-generated workflow main.go calls. It connects
// to the host over stdin+stdout, performs the wire handshake, binds the
// vault resolver, decodes the input payload, runs the user's Run function,
// and exits with code 0 on success or 1 on error.
//
// Generated workflow main looks like:
//
//	func main() {
//	    runtime.Serve(Workflow, Trigger, Run)
//	}
//
// The signature is generic over Input so user code keeps strong typing
// at the call site without runtime reflection beyond the JSON unmarshal
// at the boundary.
func Serve[I any](wf reactor.Workflow, trigger reactor.Trigger, run func(ctx context.Context, flow reactor.Flow, in I) error) {
	if err := serve(os.Stdin, os.Stdout, wf, trigger, run); err != nil {
		fmt.Fprintln(os.Stderr, "reactor serve:", err)
		os.Exit(1)
	}
}

func serve[I any](in io.Reader, out io.Writer, wf reactor.Workflow, _ reactor.Trigger, run func(ctx context.Context, flow reactor.Flow, in I) error) error {
	ctx := context.Background()
	pf := New(in, out, nil)
	defer pf.Done()

	// Wait for the host's Hello so runID is pinned before user code runs.
	// Bound the wait to 10 seconds so a misconfigured pipe fails fast
	// rather than hanging the workflow process indefinitely.
	helloCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pf.WaitHello(helloCtx); err != nil {
		return fmt.Errorf("await host hello: %w", err)
	}

	// Wire vault resolver so user code's vault.MustGet routes over the pipe.
	vault.BindFunc(func(ctx context.Context, id string) (vault.Secret, error) {
		return pf.FetchSecret(ctx, id)
	})
	// ConnectorGet uses a host-owned account origin and token. An older host
	// without the advertised broker capability fails before sending a frame.
	restoreConnector := reactorhttp.BindConnectorRequester(pf.ConnectorRequest)
	defer restoreConnector()
	restoreMail := reactoremail.BindMailSender(pf.MailSend)
	defer restoreMail()

	var input I
	if rawInput, ok := os.LookupEnv("REACTOR_INPUT"); ok && rawInput != "" {
		if err := json.Unmarshal([]byte(rawInput), &input); err != nil {
			return fmt.Errorf("decode input: %w", err)
		}
	}

	if err := run(ctx, pf, input); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
