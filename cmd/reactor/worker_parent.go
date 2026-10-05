package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
)

const workerParentFDEnv = "REACTOR_WORKER_PARENT_FD"

// workerContextWithParentLiveness turns the same-host process spawner's
// inherited pipe into an infrastructure-shutdown signal. Docker, Kubernetes,
// and manually started workers have no pipe and keep their ordinary lifecycle.
// A parent crash closes its write end even when no SIGTERM can be sent.
func workerContextWithParentLiveness(ctx context.Context) (context.Context, func(), error) {
	raw := os.Getenv(workerParentFDEnv)
	if raw == "" {
		return ctx, func() {}, nil
	}
	if raw != "3" {
		return nil, nil, fmt.Errorf("worker: invalid %s (expected inherited descriptor 3)", workerParentFDEnv)
	}
	read := os.NewFile(3, "reactor-parent-liveness")
	if read == nil {
		return nil, nil, fmt.Errorf("worker: parent liveness descriptor is unavailable")
	}
	info, err := read.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		read.Close()
		return nil, nil, fmt.Errorf("worker: parent liveness descriptor is not a pipe")
	}
	guarded, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, read)
		if guarded.Err() == nil {
			cancel(cancelreg.ErrInfrastructureShutdown)
		}
	}()
	stop := func() {
		cancel(nil)
		read.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	return guarded, stop, nil
}
