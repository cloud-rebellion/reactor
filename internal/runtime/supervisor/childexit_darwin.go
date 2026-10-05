//go:build darwin

package supervisor

import (
	"errors"
	"syscall"
)

// kqueue reports the direct child's NOTE_EXIT without reaping it. Cmd.Wait
// runs only after the cancellation watcher has stopped, so the group leader
// keeps its PID until every possible group signal has finished.
func observeChildExit(pid int) error {
	kq, err := syscall.Kqueue()
	if err != nil {
		return err
	}
	defer syscall.Close(kq)
	changes := []syscall.Kevent_t{{
		Ident: uint64(pid), Filter: syscall.EVFILT_PROC,
		Flags: syscall.EV_ADD | syscall.EV_ONESHOT, Fflags: syscall.NOTE_EXIT,
	}}
	events := make([]syscall.Kevent_t, 1)
	for {
		n, err := syscall.Kevent(kq, changes, events, nil)
		changes = nil
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.ESRCH) {
			return nil // exited before the process filter was installed
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if events[0].Flags&syscall.EV_ERROR != 0 {
				filterErr := syscall.Errno(events[0].Data)
				if errors.Is(filterErr, syscall.ESRCH) || errors.Is(filterErr, syscall.ENOENT) {
					return nil // child exited before registration
				}
				return filterErr
			}
			return nil
		}
	}
}
