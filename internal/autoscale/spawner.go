// Package autoscale grows and shrinks the distributed-mode worker pool to
// match queue depth. The Spawner abstracts HOW a worker is started so the
// same controller drives every substrate unchanged -- it only ever calls
// Spawn/Stop/Running. Two implementations ship: ProcessSpawner (same-host
// child processes, the default) and CommandSpawner (runs the operator's own
// docker/kubectl/nomad CLI, so Docker + Kubernetes + anything else work with
// zero added dependencies).
package autoscale

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// Spawner starts and stops worker instances. Implementations own the
// lifecycle of whatever they spawn (process, container, pod) and report
// how many they are currently running.
type Spawner interface {
	// Spawn starts one worker and returns an id the controller can Stop.
	Spawn(ctx context.Context) (id string, err error)
	// Stop asks the worker with id to drain + exit (graceful).
	Stop(ctx context.Context, id string) error
	// Running is how many workers this spawner currently manages.
	Running() int
	// IDs lists the managed worker ids (newest last).
	IDs() []string
	// StopAll drains every managed worker (called on shutdown).
	StopAll(ctx context.Context)
}

// ProcessSpawner runs workers as child OS processes on the same host. It is
// the simplest, lowest-blast-radius substrate: bounded by one machine's
// resources, no orchestrator dependency, no cloud cost. Stop sends SIGTERM
// so the worker drains its in-flight runs before exiting.
type ProcessSpawner struct {
	// Binary is the path to the reactor executable (os.Executable()).
	Binary string
	// Args is the full `worker ...` argv (db, root, concurrency, etc.),
	// excluding the binary itself.
	Args []string
	// Env is the child environment (defaults to the parent's when nil).
	Env []string
	Log *slog.Logger

	mu     sync.Mutex
	procs  map[string]*exec.Cmd
	guards map[string]*os.File
	ids    []string // managed child ids in spawn order, newest last
	seq    int
}

// NewProcessSpawner builds a same-host process spawner.
func NewProcessSpawner(binary string, args, env []string, log *slog.Logger) *ProcessSpawner {
	if log == nil {
		log = slog.Default()
	}
	return &ProcessSpawner{Binary: binary, Args: args, Env: env, Log: log, procs: map[string]*exec.Cmd{}, guards: map[string]*os.File{}}
}

// Spawn starts an `reactor worker` child process.
func (p *ProcessSpawner) Spawn(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	parentRead, parentWrite, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("autoscale: parent liveness pipe: %w", err)
	}
	cmd := exec.Command(p.Binary, p.Args...)
	childEnv := p.Env
	if childEnv == nil {
		childEnv = os.Environ()
	}
	cmd.Env = make([]string, 0, len(childEnv)+1)
	for _, entry := range childEnv {
		if !strings.HasPrefix(entry, "REACTOR_WORKER_PARENT_FD=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "REACTOR_WORKER_PARENT_FD=3")
	// ExtraFiles[0] is descriptor 3 in the child. The parent keeps the write
	// end open for exactly this worker's lifetime; an abrupt serve crash
	// closes it in the kernel, so the worker drains on EOF instead of becoming
	// an invisible orphan that a new leader can duplicate beyond Max.
	cmd.ExtraFiles = []*os.File{parentRead}
	// Inherit stdout/stderr so worker logs surface alongside the daemon's.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		parentRead.Close()
		parentWrite.Close()
		return "", fmt.Errorf("autoscale: spawn worker: %w", err)
	}
	parentRead.Close()
	p.mu.Lock()
	p.seq++
	id := fmt.Sprintf("proc-%d-%d", cmd.Process.Pid, p.seq)
	p.procs[id] = cmd
	p.guards[id] = parentWrite
	p.ids = append(p.ids, id)
	p.mu.Unlock()
	p.Log.Info("autoscale: spawned worker", "id", id, "pid", cmd.Process.Pid)
	// Reap on exit so Running() reflects reality even if a worker dies on
	// its own (crash, OOM) rather than via Stop.
	go func() {
		_ = cmd.Wait()
		p.mu.Lock()
		parentWrite.Close()
		delete(p.procs, id)
		delete(p.guards, id)
		for i, tracked := range p.ids {
			if tracked == id {
				p.ids = append(p.ids[:i], p.ids[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
		p.Log.Info("autoscale: worker exited", "id", id)
	}()
	return id, nil
}

// Stop signals a managed worker to drain + exit.
func (p *ProcessSpawner) Stop(_ context.Context, id string) error {
	p.mu.Lock()
	cmd := p.procs[id]
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	p.Log.Info("autoscale: stopping worker", "id", id)
	return cmd.Process.Signal(syscall.SIGTERM)
}

// Running returns the count of managed child processes.
func (p *ProcessSpawner) Running() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.procs)
}

// IDs returns the managed worker ids.
func (p *ProcessSpawner) IDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.ids...)
}

// StopAll drains every managed worker.
func (p *ProcessSpawner) StopAll(ctx context.Context) {
	for _, id := range p.IDs() {
		_ = p.Stop(ctx, id)
	}
}
