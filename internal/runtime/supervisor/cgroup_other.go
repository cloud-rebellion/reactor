//go:build !linux

package supervisor

import (
	"log/slog"
	"syscall"
)

// cgroupHandle is a no-op on non-Linux; cgroup v2 is Linux-specific
// kernel infrastructure. macOS / Windows / FreeBSD daemons rely on the
// outer container or VM for memory + pid bounds.
type cgroupHandle struct {
	Fd       int
	Killable bool
	Cleanup  func()
}

var noopCgroupHandle = cgroupHandle{Fd: -1, Cleanup: func() {}}

func prepareCgroup(_ *slog.Logger, _ string, _ ResourceLimits) cgroupHandle {
	return noopCgroupHandle
}

func applyCgroupToSysProcAttr(_ *syscall.SysProcAttr, _ cgroupHandle) {
	// SysProcAttr.UseCgroupFD doesn't exist outside Linux; no-op.
}

func closeCgroupHandle(h cgroupHandle) {
	if h.Cleanup != nil {
		h.Cleanup()
	}
}

func (h cgroupHandle) String() string {
	return "noop"
}
