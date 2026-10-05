package autoscale

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// idPlaceholder is replaced with the worker id in every Stop argv token.
const idPlaceholder = "{id}"

// CommandSpawner starts and stops workers by running operator-provided
// commands -- `docker run`, `kubectl create`, `nomad job run`, anything that
// launches one `reactor worker`. This is the pluggable substrate for EXTERNAL
// orchestration: Reactor deliberately does NOT link the Docker SDK or
// Kubernetes client-go. It shells out to the operator's own CLI, so one
// mechanism covers every cluster manager, adds zero dependencies, and never
// pins the operator to a specific client version. The same controller that
// drives same-host processes drives this unchanged -- it only ever calls
// Spawn/Stop/Running.
//
// The spawn command's stdout (trimmed, first line) becomes the worker id:
// `docker run -d` prints the container id, `kubectl create -o name` prints
// `job.batch/<name>`. That id is substituted for {id} in the stop argv.
// Workers started this way are detached (not child processes). The built-in
// Docker and Kubernetes command shapes are reconciled against the substrate
// before scaling; custom commands cannot be probed without an operator-defined
// liveness contract. A worker's lease expires and its run requeues if it exits.
type CommandSpawner struct {
	// SpawnArgv is the command that starts one worker. Its stdout (trimmed)
	// is taken as the worker id. Must be non-empty.
	SpawnArgv []string
	// SpawnStdin, if set, is fed to the spawn command's stdin. Used by the
	// Kubernetes preset to pipe a Job manifest to `kubectl create -f -`.
	SpawnStdin []byte
	// StopArgv is the command that stops a worker. It must contain "{id}"
	// so scale-down targets the worker that Spawn returned. A missing stop
	// command cannot safely manage detached workers.
	StopArgv []string
	// Env is the environment for both commands (nil = inherit the parent's).
	Env []string
	// Timeout bounds launch and inventory/ownership probes (default 30s).
	Timeout time.Duration
	// StopTimeout bounds the stop command after ownership is checked. Built-in
	// Docker workers need a longer window for their configured drain period.
	// Zero uses Timeout.
	StopTimeout time.Duration
	Log         *slog.Logger

	mu            sync.Mutex
	ids           []string // tracked worker ids, newest last
	unaddressable map[string]struct{}
	seq           int
}

// NewCommandSpawner builds a command-driven spawner. Spawn validates that
// both commands are present and the stop command names the spawned worker.
func NewCommandSpawner(spawnArgv, stopArgv, env []string, log *slog.Logger) *CommandSpawner {
	if log == nil {
		log = slog.Default()
	}
	return &CommandSpawner{SpawnArgv: spawnArgv, StopArgv: stopArgv, Env: env, Log: log, unaddressable: map[string]struct{}{}}
}

func (c *CommandSpawner) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 30 * time.Second
}

func (c *CommandSpawner) stopTimeout() time.Duration {
	if c.StopTimeout > 0 {
		return c.StopTimeout
	}
	return c.timeout()
}

// Spawn runs the spawn command and tracks the worker by the id it prints.
func (c *CommandSpawner) Spawn(ctx context.Context) (string, error) {
	if len(c.SpawnArgv) == 0 {
		return "", fmt.Errorf("autoscale: CommandSpawner has no spawn command")
	}
	if err := c.validateStopCommand(); err != nil {
		return "", err
	}
	spawnArgv, spawnStdin, err := c.managedSpawn()
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, spawnArgv[0], spawnArgv[1:]...)
	if c.Env != nil {
		cmd.Env = c.Env
	}
	if len(spawnStdin) > 0 {
		cmd.Stdin = bytes.NewReader(spawnStdin)
	}
	var stdout probeBuffer
	cmd.Stdout = &stdout
	// Launcher stderr may contain provider URLs, credentials, or payloads.
	// The exit status is enough to report failure without persisting that text.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		// No launcher process ran, so this attempt cannot have created a
		// detached worker. Leave the capacity slot free for a later retry.
		return "", fmt.Errorf("autoscale: spawn command could not start: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		// A launcher can create the worker and then fail before reporting its
		// ID (including a CLI timeout). With no reliable stop target, freeing
		// this slot would let subsequent ticks exceed the configured maximum.
		id := c.reserveUnaddressable()
		c.Log.Warn("autoscale: spawn outcome unknown; capacity slot reserved until operator recovery", "id", id, "err", err)
		return "", fmt.Errorf("autoscale: spawn command failed after start; capacity slot %s reserved: %w", id, err)
	}

	c.mu.Lock()
	c.seq++
	id := firstLine(stdout.String())
	if !safeWorkerID(id) {
		// A launcher may have started a worker without returning a usable
		// identity. Keep that launch counted against Max, but never
		// substitute untrusted shell metacharacters into a stop command or
		// pretend the synthetic handle can target the real worker.
		id = fmt.Sprintf("cmd-%d", c.seq)
		c.unaddressable[id] = struct{}{}
	}
	c.ids = append(c.ids, id)
	c.mu.Unlock()
	if c.isUnaddressable(id) {
		c.Log.Warn("autoscale: spawn returned no safe worker id; handle retained until operator recovery", "id", id)
	}
	c.Log.Info("autoscale: spawned worker", "id", id)
	return id, nil
}

// Stop runs the stop command for id and, on success, drops it from tracking.
// On failure the worker stays tracked so the next tick retries rather than
// silently leaking it.
func (c *CommandSpawner) Stop(ctx context.Context, id string) error {
	if err := c.validateStopCommand(); err != nil {
		return err
	}
	if !safeWorkerID(id) {
		return fmt.Errorf("autoscale: unsafe worker id refused")
	}
	if c.isUnaddressable(id) {
		return fmt.Errorf("autoscale: worker %q has no launcher-provided id; cannot safely stop", id)
	}
	if c.presetPrefix() {
		if _, supported := c.probeTarget(); !supported {
			return fmt.Errorf("autoscale: built-in detached worker command shape is unrecognized")
		}
	}
	argv := substituteID(c.StopArgv, id)
	if target, supported := c.probeTarget(); supported {
		fleet, err := c.fleetID()
		if err != nil {
			return err
		}
		probeCtx, cancelProbe := context.WithTimeout(ctx, c.timeout())
		exists, err := c.checkOwned(probeCtx, target, id, fleet)
		cancelProbe()
		if err != nil {
			return err
		}
		if !exists {
			c.untrack(id)
			return nil
		}
	}
	cctx, cancel := context.WithTimeout(ctx, c.stopTimeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	if c.Env != nil {
		cmd.Env = c.Env
	}
	var stderr probeBuffer
	cmd.Stderr = &stderr
	c.Log.Info("autoscale: stopping worker", "id", id)
	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		// Detached workers may finish and remove themselves before the
		// controller's stop command runs (for example Docker with --rm).
		// Treat that terminal state as success so a stale handle cannot pin
		// Running() at the autoscaler maximum forever.
		if !stderr.overflow && stopTargetGone(argv, stderrText, id) {
			c.untrack(id)
			c.Log.Info("autoscale: worker already gone", "id", id)
			return nil
		}
		c.Log.Warn("autoscale: stop command failed (kept for retry)", "id", id, "err", err)
		return fmt.Errorf("autoscale: stop command failed: %w", err)
	}
	c.untrack(id)
	return nil
}

func stopTargetGone(argv []string, stderr, id string) bool {
	// Only a Docker error naming the exact container being removed proves
	// that this stop target is gone. A generic "not found" can refer to an
	// unrelated namespace, context, or credential.
	if len(argv) == 0 || filepath.Base(argv[0]) != "docker" || !dockerTargetMissing(stderr, id) {
		return false
	}
	return len(argv) == 4 && argv[1] == "rm" && argv[2] == "-f" && argv[3] == id ||
		len(argv) == 7 && argv[1] == "stop" && argv[2] == "--signal" && argv[3] == "SIGTERM" &&
			argv[4] == "--time" && argv[6] == id
}

func (c *CommandSpawner) validateStopCommand() error {
	if len(c.StopArgv) == 0 {
		return fmt.Errorf("autoscale: CommandSpawner has no stop command")
	}
	for _, arg := range c.StopArgv {
		if strings.Contains(arg, idPlaceholder) {
			return nil
		}
	}
	return fmt.Errorf("autoscale: CommandSpawner stop command must contain %s", idPlaceholder)
}

// Running returns the number of tracked workers. The controller calls
// Reconcile before using this count for a scaling decision.
func (c *CommandSpawner) Running() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ids)
}

// IDs returns the tracked worker ids, newest last.
func (c *CommandSpawner) IDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.ids))
	copy(out, c.ids)
	return out
}

// StopAll stops every tracked worker.
func (c *CommandSpawner) StopAll(ctx context.Context) {
	for _, id := range c.IDs() {
		if err := c.Stop(ctx, id); err != nil {
			c.Log.Warn("autoscale: shutdown stop failed; detached worker remains tracked", "id", id, "err", err)
		}
	}
}

func (c *CommandSpawner) untrack(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.unaddressable, id)
	for i, v := range c.ids {
		if v == id {
			c.ids = append(c.ids[:i], c.ids[i+1:]...)
			return
		}
	}
}

func (c *CommandSpawner) track(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.ids {
		if existing == id {
			return
		}
	}
	c.ids = append(c.ids, id)
}

func (c *CommandSpawner) isUnaddressable(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, found := c.unaddressable[id]
	return found
}

func (c *CommandSpawner) reserveUnaddressable() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	id := fmt.Sprintf("cmd-%d", c.seq)
	c.unaddressable[id] = struct{}{}
	c.ids = append(c.ids, id)
	return id
}

// safeWorkerID accepts ordinary single-token worker ids and the exact
// job.batch/<name> shape returned by the built-in Kubernetes spawner. Other
// slashes are excluded so custom path-based stop commands cannot receive a
// traversal-shaped launcher id.
func safeWorkerID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	if strings.Contains(id, "/") {
		const prefix = "job.batch/"
		if !strings.HasPrefix(id, prefix) {
			return false
		}
		name := strings.TrimPrefix(id, prefix)
		if len(name) == 0 || len(name) > 63 {
			return false
		}
		for i := 0; i < len(name); i++ {
			ch := name[i]
			alnum := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9'
			if !alnum && (i == 0 || i == len(name)-1 || ch != '-') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		alnum := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
		if alnum {
			continue
		}
		if i == 0 || ch != '-' && ch != '_' && ch != '.' && ch != ':' && ch != '@' {
			return false
		}
	}
	return true
}

// substituteID returns a copy of argv with every "{id}" token replaced by id.
func substituteID(argv []string, id string) []string {
	out := make([]string, len(argv))
	for i, tok := range argv {
		out[i] = strings.ReplaceAll(tok, idPlaceholder, id)
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
