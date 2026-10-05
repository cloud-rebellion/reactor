package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	// A direct workflow exit cannot depend on a descendant's stderr or
	// stdout handle reaching EOF. These bounds apply only after the direct
	// process exits; long-running workflows with open protocol output are
	// unaffected.
	childExitPipeWait          = time.Second
	childExitOutputIdleTimeout = time.Second
	childExitOutputMaxDrain    = 3 * time.Second
	// EOF from a still-running workflow is also bounded: the protocol has
	// ended, so the direct process must finish its teardown promptly.
	childExitAfterEOFGrace = 2 * time.Second
)

// childOutputReader gives buffered protocol frames a chance to drain after
// the direct process exits, then fails if a descendant still holds stdout.
// The exit observer sets the first deadline to interrupt an in-flight read;
// later reads refresh the idle window without extending the absolute drain
// limit.
type childOutputReader struct {
	pipe             *os.File
	processExited    <-chan struct{}
	absoluteDeadline time.Time // written before processExited closes
}

// childExitMonitor reports direct-process exit before inherited protocol
// handles necessarily reach EOF. Unix implementations observe without
// reaping, so process-group signals remain tied to the original leader until
// wait is called. Other platforms retain their direct-process kill fallback.
type childExitMonitor struct {
	observed <-chan error
	wait     func() error
}

func startChildExitMonitor(cmd *exec.Cmd, onExit func(error)) childExitMonitor {
	return newChildExitMonitor(cmd, onExit)
}

func (r *childOutputReader) Read(p []byte) (int, error) {
	select {
	case <-r.processExited:
		deadline := time.Now().Add(childExitOutputIdleTimeout)
		if deadline.After(r.absoluteDeadline) {
			deadline = r.absoluteDeadline
		}
		if !time.Now().Before(deadline) {
			return 0, fmt.Errorf("supervisor: workflow output exceeded post-exit drain window: %w", os.ErrDeadlineExceeded)
		}
		if err := r.pipe.SetReadDeadline(deadline); err != nil {
			return 0, fmt.Errorf("supervisor: set exited workflow output deadline: %w", err)
		}
	default:
	}
	n, err := r.pipe.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return n, fmt.Errorf("supervisor: workflow output held open after process exit: %w", err)
	}
	return n, err
}
