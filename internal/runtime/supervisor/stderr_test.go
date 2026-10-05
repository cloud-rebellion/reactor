package supervisor

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestStderrForwarderBoundsWorkflowOutput(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	writer := newStderrForwarder(log)
	payload := bytes.Repeat([]byte("x"), maxWorkflowStderrBytes+maxWorkflowStderrChunk)
	n, err := writer.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("write count = %d, want %d", n, len(payload))
	}
	if !strings.Contains(logs.String(), "workflow stderr truncated") {
		t.Fatal("missing truncation event")
	}
	if len(logs.Bytes()) >= len(payload) {
		t.Fatalf("bounded log grew to %d bytes for %d-byte child output", len(logs.Bytes()), len(payload))
	}
	if n, err := io.WriteString(writer, "discarded after cap"); err != nil || n == 0 {
		t.Fatalf("post-cap write = %d, %v", n, err)
	}
}
