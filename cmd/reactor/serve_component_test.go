package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestRunDaemonComponentReturnsUnexpectedError(t *testing.T) {
	want := errors.New("listener failed")
	got := runDaemonComponent(slog.New(slog.NewTextHandler(io.Discard, nil)), "http_server", func() error {
		return want
	})
	if !errors.Is(got, want) {
		t.Fatalf("runDaemonComponent error = %v, want %v", got, want)
	}
}

func TestRunDaemonComponentTurnsPanicIntoError(t *testing.T) {
	got := runDaemonComponent(slog.New(slog.NewTextHandler(io.Discard, nil)), "http_server", func() error {
		panic("bind panic")
	})
	if got == nil || !strings.Contains(got.Error(), "bind panic") {
		t.Fatalf("runDaemonComponent panic error = %v, want panic text", got)
	}
}

func TestRunDaemonComponentIgnoresContextCancellation(t *testing.T) {
	got := runDaemonComponent(slog.New(slog.NewTextHandler(io.Discard, nil)), "scheduler", func() error {
		return context.Canceled
	})
	if got != nil {
		t.Fatalf("runDaemonComponent context cancellation = %v, want nil", got)
	}
}
