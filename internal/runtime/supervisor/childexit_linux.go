//go:build linux

package supervisor

import (
	"errors"

	"golang.org/x/sys/unix"
)

// waitid with WNOWAIT observes exit while leaving the workflow group leader
// unreaped. Its PID cannot be reused until Cmd.Wait after cancellation and
// abnormal-exit signalling have both finished.
func observeChildExit(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}
