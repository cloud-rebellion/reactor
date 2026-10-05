package supervisor

// ResourceLimits caps the workflow subprocess so a misbehaving AI-generated
// workflow can't fork-bomb the host or eat unbounded memory. Zero values
// mean "leave the kernel default in place"; the supervisor fills in sane
// defaults before applying via applyRlimits.
//
// Two enforcement layers on Linux. CPU time, open files, and process count
// go through prlimit(2) (always attempted). Memory is enforced ONLY by the
// optional cgroup v2 layer (CgroupRoot non-empty + /sys/fs/cgroup is v2 +
// the daemon can mkdir a child), which caps resident memory via memory.max
// and lets pressure OOM-kill cleanly. Memory is intentionally NOT capped
// with RLIMIT_AS: a virtual-address-space limit crashes the Go child at
// startup (see rlimit_linux.go). Without cgroup v2 the memory fence is the
// daemon's own container/systemd unit.
//
// Enforcement is Linux-only; other GOOS values are no-ops and rely on
// the operator running inside a container or VM as the outer fence.
type ResourceLimits struct {
	// MemoryMaxBytes caps resident memory via cgroup memory.max (Linux,
	// cgroup v2 only). 0 means default. NOT applied via RLIMIT_AS: a
	// virtual-address-space cap crashes the Go child at startup.
	MemoryMaxBytes uint64

	// CPUSeconds caps RLIMIT_CPU (CPU time in seconds). 0 means default.
	CPUSeconds uint64

	// MaxOpenFiles caps RLIMIT_NOFILE. 0 means default.
	MaxOpenFiles uint64

	// MaxProcesses caps RLIMIT_NPROC (fork-bomb guard). 0 means default.
	MaxProcesses uint64

	// CgroupRoot, when set, enables cgroup v2 enforcement. Default
	// "/sys/fs/cgroup" if you want it on; the empty string disables
	// the cgroup path entirely (prlimit-only). The daemon creates a
	// per-run cgroup at <root>/reactor/<run_id> with memory.max set
	// to MemoryMaxBytes and pids.max set to MaxProcesses, then
	// passes the cgroup fd via SysProcAttr.UseCgroupFD so the child
	// lands in the cgroup atomically at clone3 time. If the path is
	// unavailable, the supervisor keeps the prlimit-only fallback unless
	// RequireCgroup is true.
	CgroupRoot string

	// RequireCgroup makes a configured cgroup root an admission requirement.
	// When true, a run is refused unless the supervisor can create a per-run
	// cgroup and the host exposes cgroup.kill for descendant cleanup. This is
	// useful when workflows are treated as hostile code; leaving it false
	// retains the resource-limit-only fallback for development hosts.
	RequireCgroup bool
}

// DefaultResourceLimits returns the v0.1 defaults: 512 MiB resident memory
// (cgroup memory.max), 60 CPU-seconds, 256 open files, 64 child processes.
// Picked to let the SDK + a workflow with a few HTTP clients run comfortably
// while still stopping a misbehaving generator from taking down the host.
func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		MemoryMaxBytes: 512 * 1024 * 1024,
		CPUSeconds:     60,
		MaxOpenFiles:   256,
		MaxProcesses:   64,
	}
}

// withDefaults fills any zero field with the v0.1 default. Tests can pass
// a partial ResourceLimits to override only what they care about.
func (r ResourceLimits) withDefaults() ResourceLimits {
	d := DefaultResourceLimits()
	if r.MemoryMaxBytes == 0 {
		r.MemoryMaxBytes = d.MemoryMaxBytes
	}
	if r.CPUSeconds == 0 {
		r.CPUSeconds = d.CPUSeconds
	}
	if r.MaxOpenFiles == 0 {
		r.MaxOpenFiles = d.MaxOpenFiles
	}
	if r.MaxProcesses == 0 {
		r.MaxProcesses = d.MaxProcesses
	}
	return r
}
