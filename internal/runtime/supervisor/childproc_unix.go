//go:build linux || darwin

package supervisor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killChildProcess stops the entire workflow process group. The direct child
// remains unreaped until Cmd.Wait, so its process-group id cannot be reused by
// an unrelated process while this call runs.
func killChildProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func cleanupChildGroupAfterExit(cmd *exec.Cmd) {
	_ = killChildProcess(cmd)
}
