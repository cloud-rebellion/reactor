//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// cgroupHandle bundles an open cgroup directory fd with a cleanup
// closure that removes the cgroup directory after the child exits.
// The Fd field is -1 when the cgroup path is unavailable (no cgroup v2,
// no write permission, missing controllers) and the caller falls back
// to prlimit-only enforcement.
type cgroupHandle struct {
	Fd int
	// Killable reports whether this kernel exposes cgroup.kill. Without it,
	// the direct child is bounded but descendants can survive the run.
	Killable bool
	Cleanup  func()
}

// noopCgroupHandle is the fallback returned when cgroup v2 isn't
// available. Fd=-1 tells the supervisor to skip SysProcAttr.UseCgroupFD;
// the prlimit path still runs.
var noopCgroupHandle = cgroupHandle{Fd: -1, Cleanup: func() {}}

// prepareCgroup tries to create a child cgroup at
// <root>/reactor/<runID> with memory.max + pids.max set from lim, then
// returns a handle to its fd. Any failure (not a cgroup v2 mount, no
// write permission, controllers not delegated) returns the noop handle
// + logs a warning. The supervisor never aborts on cgroup failure.
func prepareCgroup(log *slog.Logger, runID string, lim ResourceLimits) cgroupHandle {
	if lim.CgroupRoot == "" {
		return noopCgroupHandle
	}
	lim = lim.withDefaults()

	if !isCgroupV2(lim.CgroupRoot) {
		log.Debug("cgroup: skipping (not cgroup v2)", "root", lim.CgroupRoot)
		return noopCgroupHandle
	}

	// Ensure the parent "reactor" cgroup exists + has memory + pids
	// controllers enabled in subtree_control. This is idempotent.
	parent := filepath.Join(lim.CgroupRoot, "reactor")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		log.Warn("cgroup: parent mkdir failed; falling back to prlimit-only",
			"path", parent, "err", err)
		return noopCgroupHandle
	}
	// Best-effort enable controllers. If subtree_control doesn't exist
	// or we can't write it, the child cgroup may lack controllers; we
	// still try the child path and let mkdir/limit-set fail loudly if
	// the controllers are unavailable.
	_ = os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"),
		[]byte("+memory +pids"), 0o644)

	child := filepath.Join(parent, sanitiseRunID(runID))
	if err := os.MkdirAll(child, 0o755); err != nil {
		log.Warn("cgroup: child mkdir failed; falling back to prlimit-only",
			"path", child, "err", err)
		return noopCgroupHandle
	}

	// cgroup.kill was added to cgroup v2 in Linux 5.14. Keep the capability
	// on the handle so strict callers can refuse a run on older kernels rather
	// than pretending that descendants are contained.
	_, killStatErr := os.Stat(filepath.Join(child, "cgroup.kill"))
	killable := false
	if killStatErr == nil {
		// The cgroup is empty before cmd.Start, so this probe is harmless and
		// proves that the daemon can actually write the kernel control file;
		// merely seeing a mode entry is insufficient because delegation/ACLs
		// can still make the write fail.
		killable = killCgroupProcesses(child) == nil
	}
	cleanup := func() {
		// A workflow may fork descendants and exit cleanly. Kill the entire
		// per-run cgroup before removing it so those descendants cannot keep
		// operating against the daemon's journal or credentials. On older
		// kernels cgroup.kill is absent; optional mode retains the historical
		// best-effort cleanup and strict mode refuses the run below.
		if err := killCgroupProcesses(child); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn("cgroup: descendant cleanup failed", "path", child, "err", err)
		}
		_ = os.Remove(child)
	}

	if lim.MemoryMaxBytes > 0 {
		if err := os.WriteFile(filepath.Join(child, "memory.max"),
			[]byte(strconv.FormatUint(lim.MemoryMaxBytes, 10)), 0o644); err != nil {
			log.Warn("cgroup: memory.max write failed (controller likely undelegated); falling back",
				"err", err)
			cleanup()
			return noopCgroupHandle
		}
	}
	if lim.MaxProcesses > 0 {
		if err := os.WriteFile(filepath.Join(child, "pids.max"),
			[]byte(strconv.FormatUint(lim.MaxProcesses, 10)), 0o644); err != nil {
			log.Warn("cgroup: pids.max write failed (controller likely undelegated); falling back",
				"err", err)
			cleanup()
			return noopCgroupHandle
		}
	}

	fd, err := syscall.Open(child, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		log.Warn("cgroup: open dir fd failed; falling back to prlimit-only",
			"path", child, "err", err)
		cleanup()
		return noopCgroupHandle
	}
	return cgroupHandle{
		Fd:       fd,
		Killable: killable,
		Cleanup: func() {
			syscall.Close(fd)
			cleanup()
		},
	}
}

// killCgroupProcesses asks the kernel to terminate every process in a v2
// cgroup, including descendants of the workflow. It is intentionally a tiny
// helper so its destructive write can be tested without requiring a mounted
// cgroup hierarchy.
func killCgroupProcesses(path string) error {
	f, err := os.OpenFile(filepath.Join(path, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString("1")
	return err
}

// isCgroupV2 reports whether the given mount root is a cgroup v2
// hierarchy. Tests both the canonical sentinel file (cgroup.controllers
// exists at the v2 root) and that the path is a directory.
func isCgroupV2(root string) bool {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return false
	}
	return true
}

// sanitiseRunID strips any path-traversal funkiness from a run id so it
// can be used directly as a cgroup directory component. Run ids are
// generated by the journal but we still defend against malformed input
// in the data path that talks to /sys.
func sanitiseRunID(runID string) string {
	if runID == "" {
		return "unknown"
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '_' || r == '-':
			return r
		default:
			return '_'
		}
	}, runID)
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean
}

// applyCgroupToSysProcAttr is a small adapter so supervisor.go doesn't
// need build-tagged access to syscall.SysProcAttr.UseCgroupFD (that
// field exists on Linux only).
func applyCgroupToSysProcAttr(attr *syscall.SysProcAttr, h cgroupHandle) {
	if h.Fd < 0 {
		return
	}
	attr.UseCgroupFD = true
	attr.CgroupFD = h.Fd
}

// closeCgroupHandle exists so the non-Linux stub can expose an
// equivalent no-op without importing this file's types directly.
func closeCgroupHandle(h cgroupHandle) {
	if h.Cleanup != nil {
		h.Cleanup()
	}
}

// String for log readability; kept here so cgroup_other.go can mirror.
func (h cgroupHandle) String() string {
	if h.Fd < 0 {
		return "noop"
	}
	return fmt.Sprintf("fd=%d", h.Fd)
}
