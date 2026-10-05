//go:build linux || darwin

package supervisor

import "os/exec"

func newChildExitMonitor(cmd *exec.Cmd, onExit func(error)) childExitMonitor {
	observed := make(chan error, 1)
	go func() {
		err := observeChildExit(cmd.Process.Pid)
		onExit(err)
		observed <- err
	}()
	return childExitMonitor{observed: observed, wait: cmd.Wait}
}
