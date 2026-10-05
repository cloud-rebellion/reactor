//go:build linux

package supervisor

import (
	"os/exec"
	"syscall"
)

// configureChildProcess applies Linux-only process lifetime hardening. The
// parent-death signal is delivered if the Reactor daemon exits unexpectedly,
// so a workflow cannot outlive the host that owns its journal and vault.
func configureChildProcess(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	// Keep descendants in the workflow's process group. CommandContext's
	// default cancellation only kills the direct child, so a forked process
	// could keep stdout open and prevent the supervisor from draining.
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error { return killChildProcess(cmd) }
}
