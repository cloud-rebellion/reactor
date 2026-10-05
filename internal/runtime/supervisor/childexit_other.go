//go:build !linux && !darwin

package supervisor

import "os/exec"

// Other platforms have no process-group signalling in this package, so a
// concurrent Wait can safely bound a descendant-held output pipe.
func newChildExitMonitor(cmd *exec.Cmd, onExit func(error)) childExitMonitor {
	observed := make(chan error, 1)
	waited := make(chan error, 1)
	go func() {
		waitErr := cmd.Wait()
		onExit(nil)
		observed <- nil
		waited <- waitErr
	}()
	return childExitMonitor{observed: observed, wait: func() error { return <-waited }}
}
