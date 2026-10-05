//go:build linux

package supervisor

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestConfigureChildProcessSetsParentDeathSignal(t *testing.T) {
	cmd := exec.Command("true")
	configureChildProcess(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("configureChildProcess left SysProcAttr nil")
	}
	if cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("Pdeathsig = %v, want SIGKILL", cmd.SysProcAttr.Pdeathsig)
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Fatal("workflow child did not get a separate process group")
	}
	if cmd.Cancel == nil {
		t.Fatal("workflow child cancellation is not configured")
	}
}
