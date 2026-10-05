//go:build !linux && !darwin

package supervisor

import (
	"os"
	"os/exec"
)

// configureChildProcess has no portable parent-death equivalent. The daemon
// still owns cancellation and the deployment's outer process supervisor is
// responsible for cleaning up after an unexpected host exit.
func configureChildProcess(_ *exec.Cmd) {}

func killChildProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}

func cleanupChildGroupAfterExit(_ *exec.Cmd) {}
