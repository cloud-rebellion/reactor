package supervisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/wire"
)

func TestHandleLogKeepsWorkflowTextOutOfHostRecord(t *testing.T) {
	var host bytes.Buffer
	var local string
	sup := &Supervisor{
		RunID: "run-log-projection",
		Log:   slog.New(slog.NewTextHandler(&host, nil)),
		LogSink: func(_ string, line string) {
			local = line
		},
	}
	d := &dispatcher{sup: sup}
	f, err := wire.Wrap(1, 0, wire.KindLog, wire.Log{
		Level: "ERROR",
		Msg:   "credential=workflow-secret",
		Attrs: map[string]any{"status": "failed", "token": "workflow-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.handleLog(f)
	if strings.Contains(host.String(), "workflow-secret") || strings.Contains(host.String(), "credential") {
		t.Fatalf("workflow text reached the host record: %s", host.String())
	}
	if !strings.Contains(host.String(), "workflow log") || !strings.Contains(host.String(), "run-log-projection") {
		t.Fatalf("host record lost its operational context: %s", host.String())
	}
	if !strings.Contains(local, "workflow-secret") {
		t.Fatalf("tenant-local log lost workflow detail: %s", local)
	}
}

func TestUnknownWorkflowFrameKindDoesNotReachHostLog(t *testing.T) {
	var input, host bytes.Buffer
	const privateKind = "oauth-access-token-from-child"
	f, err := wire.Wrap(1, 0, wire.Kind(privateKind), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.NewEncoder(&input).Encode(f); err != nil {
		t.Fatal(err)
	}
	d := &dispatcher{
		sup: &Supervisor{Log: slog.New(slog.NewTextHandler(&host, nil))},
		dec: wire.NewDecoder(&input),
	}
	if err := d.loop(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("loop error = %v, want EOF", err)
	}
	if strings.Contains(host.String(), privateKind) {
		t.Fatalf("child-controlled frame kind reached host log: %s", host.String())
	}
}
