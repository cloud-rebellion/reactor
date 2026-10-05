package autoscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxProbeOutput = 256 << 10

type workerState uint8

const (
	workerLive workerState = iota
	workerTerminal
	workerMissing
)

type probeTarget struct {
	command   string
	namespace string
	kind      string
}

// Reconcile adopts exact-fleet workers left by a previous leader and removes
// only workers whose terminal state can be proved by the built-in Docker or
// Kubernetes CLI. Probe errors retain every tracked handle and stop scaling.
// The whole pass, including cleanup, is bounded by Timeout (30s by default).
func (c *CommandSpawner) Reconcile(ctx context.Context) error {
	target, supported := c.probeTarget()
	if !supported {
		if c.presetPrefix() {
			return fmt.Errorf("autoscale: built-in detached worker command shape is unrecognized")
		}
		return nil // Custom command spawners have no general liveness contract.
	}
	fleet, err := c.fleetID()
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	states, err := c.inventory(probeCtx, target, fleet)
	if err != nil {
		return err
	}
	ids := c.IDs()
	// Probe every previously tracked handle absent from inventory. Listing can
	// lag a spawn or a label can have changed; neither permits freeing a slot
	// until an exact target probe proves the worker disappeared.
	for _, id := range ids {
		if c.isUnaddressable(id) {
			continue
		}
		if _, found := states[id]; found {
			continue
		}
		var state workerState
		switch target.kind {
		case "docker":
			if strings.Contains(id, "/") {
				return fmt.Errorf("autoscale: Docker worker has unexpected id shape")
			}
			state, err = c.probeDocker(probeCtx, target.command, id)
		case "kubernetes":
			if !strings.HasPrefix(id, "job.batch/") {
				return fmt.Errorf("autoscale: Kubernetes worker has unexpected id shape")
			}
			state, err = c.probeJob(probeCtx, target.command, target.namespace, id)
		}
		if err != nil {
			return err
		}
		if state != workerMissing {
			return fmt.Errorf("autoscale: tracked worker is absent from fleet inventory but still exists")
		}
		states[id] = workerMissing
	}
	// Do not mutate the count until the whole inventory and all exact probes
	// succeed. A partial read could otherwise drop live capacity from Max.
	for _, id := range sortedStateIDs(states) {
		switch states[id] {
		case workerMissing:
			c.untrack(id)
			c.Log.Info("autoscale: detached worker already gone", "id", id)
		case workerTerminal:
			// A terminal Docker container cannot benefit from a graceful stop.
			// Remove it without force after rechecking fleet ownership. Running
			// containers take the separate signal-and-drain Stop path.
			var err error
			if target.kind == "docker" {
				err = c.removeTerminalDocker(probeCtx, target.command, id, fleet)
			} else {
				err = c.Stop(probeCtx, id)
			}
			if err != nil {
				return fmt.Errorf("autoscale: terminal worker cleanup failed: %w", err)
			}
		case workerLive:
			c.track(id)
		}
	}
	return nil
}

func (c *CommandSpawner) presetPrefix() bool {
	spawn := c.SpawnArgv
	if len(spawn) >= 6 && filepath.Base(spawn[0]) == "docker" &&
		spawn[1] == "run" && spawn[2] == "-d" && spawn[3] == "--rm" &&
		spawn[4] == "--label" && spawn[5] == "reactor-worker=1" {
		return true
	}
	return len(spawn) >= 6 && filepath.Base(spawn[0]) == "kubectl" &&
		spawn[1] == "create" && spawn[2] == "--namespace" &&
		spawn[4] == "-f" && spawn[5] == "-"
}

// Recognize only the exact command structure emitted by buildSpawner. A
// custom command may happen to call docker or kubectl but have other target
// semantics; it must not inherit the built-in terminal-state rules.
func (c *CommandSpawner) probeTarget() (probeTarget, bool) {
	spawn, stop := c.SpawnArgv, c.StopArgv
	if len(spawn) >= 18 && len(stop) == 7 && spawn[0] == stop[0] &&
		filepath.Base(spawn[0]) == "docker" &&
		spawn[1] == "run" && spawn[2] == "-d" && spawn[3] == "--rm" &&
		spawn[4] == "--label" && spawn[5] == "reactor-worker=1" &&
		spawn[len(spawn)-12] == "--env" && spawn[len(spawn)-11] == "REACTOR_DB_URL" &&
		spawn[len(spawn)-10] == "--env" && spawn[len(spawn)-9] == "REACTOR_MASTER_KEY" &&
		spawn[len(spawn)-8] != "" && spawn[len(spawn)-7] == "worker" &&
		spawn[len(spawn)-6] == "--root" && spawn[len(spawn)-5] != "" &&
		spawn[len(spawn)-4] == "--concurrency" && spawn[len(spawn)-3] != "" &&
		spawn[len(spawn)-2] == "--drain-timeout" &&
		stop[1] == "stop" && stop[2] == "--signal" && stop[3] == "SIGTERM" &&
		stop[4] == "--time" && stop[6] == idPlaceholder {
		drain, drainErr := time.ParseDuration(spawn[len(spawn)-1])
		seconds, secondsErr := strconv.ParseInt(stop[5], 10, 64)
		if drainErr == nil && drain > 0 && secondsErr == nil && seconds > 0 {
			minimum := int64(drain / time.Second)
			if drain%time.Second != 0 {
				minimum++
			}
			if seconds >= minimum {
				return probeTarget{command: spawn[0], kind: "docker"}, true
			}
		}
	}
	if len(spawn) == 8 && len(stop) == 6 && spawn[0] == stop[0] &&
		filepath.Base(spawn[0]) == "kubectl" &&
		spawn[1] == "create" && spawn[2] == "--namespace" && spawn[3] != "" &&
		spawn[4] == "-f" && spawn[5] == "-" && spawn[6] == "-o" && spawn[7] == "name" &&
		stop[1] == "delete" && stop[2] == "--namespace" && stop[3] == spawn[3] &&
		stop[4] == "--ignore-not-found" && stop[5] == idPlaceholder {
		return probeTarget{command: spawn[0], namespace: spawn[3], kind: "kubernetes"}, true
	}
	return probeTarget{}, false
}

// removeTerminalDocker is only called after inventory proved a worker exited.
// It rechecks the exact fleet label and uses non-forced rm so an unexpected
// concurrent restart cannot turn terminal cleanup into SIGKILL.
func (c *CommandSpawner) removeTerminalDocker(ctx context.Context, command, id, fleet string) error {
	exists, err := c.checkOwned(ctx, probeTarget{command: command, kind: "docker"}, id, fleet)
	if err != nil {
		return err
	}
	if !exists {
		c.untrack(id)
		return nil
	}
	_, stderr, err := c.runProbe(ctx, command, "rm", id)
	if err != nil && !(ctx.Err() == nil && dockerTargetMissing(stderr, id)) {
		return fmt.Errorf("autoscale: remove terminal Docker worker: %w", err)
	}
	c.untrack(id)
	return nil
}

func (c *CommandSpawner) probeDocker(ctx context.Context, command, id string) (workerState, error) {
	stdout, stderr, err := c.runProbe(ctx, command, "inspect", "--type=container", "--format={{.State.Status}}", id)
	if err != nil {
		if ctx.Err() == nil && dockerTargetMissing(stderr, id) {
			return workerMissing, nil
		}
		return workerLive, fmt.Errorf("autoscale: Docker worker probe failed: %w", err)
	}
	switch strings.TrimSpace(stdout) {
	case "running", "created", "restarting", "paused", "removing":
		return workerLive, nil
	case "exited", "dead":
		return workerTerminal, nil
	default:
		return workerLive, fmt.Errorf("autoscale: Docker worker probe returned unknown state")
	}
}

func dockerTargetMissing(stderr, id string) bool {
	message := strings.TrimSpace(stderr)
	if strings.Contains(message, "\n") {
		return false
	}
	message = strings.TrimPrefix(message, "Error response from daemon: ")
	message = strings.TrimPrefix(message, "Error: ")
	for _, prefix := range []string{"No such object: ", "No such container: "} {
		if strings.EqualFold(message, prefix+id) {
			return true
		}
	}
	return false
}

func (c *CommandSpawner) probeJob(ctx context.Context, command, namespace, id string) (workerState, error) {
	name := strings.TrimPrefix(id, "job.batch/")
	stdout, stderr, err := c.runProbe(ctx, command, "get", "--namespace", namespace, id, "-o=json")
	if err != nil {
		if ctx.Err() == nil && jobTargetMissing(stderr, name) {
			return workerMissing, nil
		}
		return workerLive, fmt.Errorf("autoscale: Kubernetes Job probe failed: %w", err)
	}
	var job struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(stdout), &job); err != nil {
		return workerLive, fmt.Errorf("autoscale: Kubernetes Job probe returned invalid JSON: %w", err)
	}
	if job.Kind != "Job" || job.Metadata.Name != name ||
		(job.Metadata.Namespace != "" && job.Metadata.Namespace != namespace) {
		return workerLive, fmt.Errorf("autoscale: Kubernetes Job probe returned unexpected target")
	}
	for _, condition := range job.Status.Conditions {
		if condition.Status == "True" && (condition.Type == "Complete" || condition.Type == "Failed") {
			return workerTerminal, nil
		}
	}
	return workerLive, nil
}

func jobTargetMissing(stderr, name string) bool {
	// Match the object name, not an unrelated missing namespace or context.
	message := strings.TrimSpace(stderr)
	for _, kind := range []string{"jobs", "jobs.batch"} {
		if message == "Error from server (NotFound): "+kind+" \""+name+"\" not found" {
			return true
		}
	}
	return false
}

func (c *CommandSpawner) runProbe(ctx context.Context, command string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	if c.Env != nil {
		cmd.Env = c.Env
	}
	var stdout, stderr probeBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stdout.overflow || stderr.overflow {
		return "", "", fmt.Errorf("autoscale: worker probe output exceeded %d bytes", maxProbeOutput)
	}
	return stdout.String(), stderr.String(), err
}

// A failed CLI must not be able to grow Reactor's memory with unbounded
// output. Keep enough output for a normal Job JSON object or CLI error.
type probeBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *probeBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > maxProbeOutput {
		b.overflow = true
		p = p[:max(0, maxProbeOutput-b.Len())]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
