//go:build darwin

package supervisor

import (
	"os/exec"
	"syscall"
)

// macOS has no parent-death signal, but a separate process group lets
// cancellation stop workflow descendants that inherited protocol pipes.
func configureChildProcess(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error { return killChildProcess(cmd) }
}
