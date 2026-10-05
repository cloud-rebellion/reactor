package autoscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const fleetLabel = "reactor-autoscale-fleet"
const fleetEnv = "REACTOR_AUTOSCALE_FLEET_ID"
const maxInventoryWorkers = 1024

// A stable, operator-chosen fleet ID lets a new leader adopt detached workers
// from its predecessor without accidentally managing another Reactor fleet.
// An empty or malformed ID disables built-in detached spawning: a generic
// reactor-worker label alone cannot establish ownership after a restart.
func (c *CommandSpawner) fleetID() (string, error) {
	id := os.Getenv(fleetEnv)
	if c.Env != nil {
		id = ""
		for _, entry := range c.Env {
			if strings.HasPrefix(entry, fleetEnv+"=") {
				id = strings.TrimPrefix(entry, fleetEnv+"=")
			}
		}
	}
	if err := ValidateFleetID(id); err != nil {
		return "", err
	}
	return id, nil
}

// ValidateFleetID is shared by the command spawner and serve's startup
// configuration gate, so an unusable detached autoscaler fails before ready.
func ValidateFleetID(id string) error {
	if len(id) == 0 || len(id) > 63 {
		return fmt.Errorf("autoscale: %s must be a stable 1-63 character fleet label for detached workers", fleetEnv)
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		alnum := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9'
		if !alnum && (i == 0 || i == len(id)-1 || ch != '-') {
			return fmt.Errorf("autoscale: %s must use lowercase letters, digits, and internal hyphens", fleetEnv)
		}
	}
	return nil
}

func (c *CommandSpawner) managedSpawn() ([]string, []byte, error) {
	target, supported := c.probeTarget()
	if !supported {
		if c.presetPrefix() {
			return nil, nil, fmt.Errorf("autoscale: built-in detached worker command shape is unrecognized")
		}
		return c.SpawnArgv, c.SpawnStdin, nil
	}
	fleet, err := c.fleetID()
	if err != nil {
		return nil, nil, err
	}
	if target.kind == "docker" {
		// Docker options supplied by the operator sit between the fixed
		// reactor-worker label and the final image/worker command. Neither a
		// conflicting label nor an opaque label file may erase our inventory
		// marker; the fleet label is appended after those options.
		optionEnd := len(c.SpawnArgv) - 12
		options := c.SpawnArgv[6:optionEnd]
		for i, option := range options {
			if option == "--label-file" || strings.HasPrefix(option, "--label-file=") {
				return nil, nil, fmt.Errorf("autoscale: Docker worker label files are incompatible with managed fleet inventory")
			}
			label := ""
			switch {
			case option == "--label" || option == "-l":
				if i+1 < len(options) {
					label = options[i+1]
				}
			case strings.HasPrefix(option, "--label="):
				label = strings.TrimPrefix(option, "--label=")
			case strings.HasPrefix(option, "-l="):
				label = strings.TrimPrefix(option, "-l=")
			}
			key, _, _ := strings.Cut(label, "=")
			if key == "reactor-worker" || key == fleetLabel {
				return nil, nil, fmt.Errorf("autoscale: Docker worker args override a managed inventory label")
			}
		}
		argv := make([]string, 0, len(c.SpawnArgv)+2)
		argv = append(argv, c.SpawnArgv[:optionEnd]...)
		argv = append(argv, "--label", fleetLabel+"="+fleet)
		argv = append(argv, c.SpawnArgv[optionEnd:]...)
		return argv, c.SpawnStdin, nil
	}
	// buildSpawner's fixed Job manifest has one top-level metadata label
	// block. Refuse to create an unlabelled Job if that shape ever changes.
	const marker = "  labels:\n    app: reactor-worker\nspec:"
	if bytes.Count(c.SpawnStdin, []byte(marker)) != 1 {
		return nil, nil, fmt.Errorf("autoscale: Kubernetes worker manifest lacks the expected Job labels")
	}
	manifest := bytes.Replace(c.SpawnStdin, []byte(marker),
		[]byte("  labels:\n    app: reactor-worker\n    "+fleetLabel+": \""+fleet+"\"\nspec:"), 1)
	return c.SpawnArgv, manifest, nil
}

// inventory returns the currently discoverable workers with this exact fleet
// label. It scans the broader Reactor label first so an unlabelled worker from
// an older release cannot be silently ignored and cause Max to be exceeded.
// Distinct labelled fleets are left completely alone.
func (c *CommandSpawner) inventory(ctx context.Context, target probeTarget, fleet string) (map[string]workerState, error) {
	switch target.kind {
	case "docker":
		return c.dockerInventory(ctx, target.command, fleet)
	case "kubernetes":
		return c.jobInventory(ctx, target.command, target.namespace, fleet)
	default:
		return nil, fmt.Errorf("autoscale: unsupported detached inventory")
	}
}

func (c *CommandSpawner) dockerInventory(ctx context.Context, command, fleet string) (map[string]workerState, error) {
	stdout, _, err := c.runProbe(ctx, command, "ps", "-a", "--no-trunc", "--filter", "label=reactor-worker=1", "--format={{.ID}}")
	if err != nil {
		return nil, fmt.Errorf("autoscale: Docker worker inventory failed: %w", err)
	}
	lines := strings.Fields(strings.TrimSpace(stdout))
	if len(lines) > maxInventoryWorkers {
		return nil, fmt.Errorf("autoscale: Docker worker inventory exceeds %d entries", maxInventoryWorkers)
	}
	states := make(map[string]workerState, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, id := range lines {
		if !safeWorkerID(id) || strings.Contains(id, "/") {
			return nil, fmt.Errorf("autoscale: Docker worker inventory returned invalid id")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("autoscale: Docker worker inventory returned duplicate id")
		}
		seen[id] = struct{}{}
		labelJSON, stderr, err := c.runProbe(ctx, command, "inspect", "--type=container", "--format={{json .Config.Labels}}", id)
		if err != nil {
			if ctx.Err() == nil && dockerTargetMissing(stderr, id) {
				continue // disappeared between list and inspect
			}
			return nil, fmt.Errorf("autoscale: Docker worker labels unavailable: %w", err)
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(labelJSON), &labels); err != nil || labels["reactor-worker"] != "1" {
			return nil, fmt.Errorf("autoscale: Docker worker inventory returned invalid labels")
		}
		owner := labels[fleetLabel]
		if owner == "" {
			return nil, fmt.Errorf("autoscale: unlabelled Reactor Docker worker makes fleet ownership ambiguous")
		}
		if owner != fleet {
			continue
		}
		state, err := c.probeDocker(ctx, command, id)
		if err != nil {
			return nil, err
		}
		states[id] = state
	}
	return states, nil
}

// StopAll and scale-down must validate the current object's fleet label at
// the delete boundary, not just rely on a previously observed inventory row.
func (c *CommandSpawner) checkOwned(ctx context.Context, target probeTarget, id, fleet string) (bool, error) {
	if target.kind == "docker" {
		if strings.Contains(id, "/") {
			return false, fmt.Errorf("autoscale: Docker stop target has unexpected id shape")
		}
		stdout, stderr, err := c.runProbe(ctx, target.command, "inspect", "--type=container", "--format={{json .Config.Labels}}", id)
		if err != nil {
			if ctx.Err() == nil && dockerTargetMissing(stderr, id) {
				return false, nil
			}
			return false, fmt.Errorf("autoscale: Docker stop ownership probe failed: %w", err)
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(stdout), &labels); err != nil ||
			labels["reactor-worker"] != "1" || labels[fleetLabel] != fleet {
			return false, fmt.Errorf("autoscale: Docker stop target is not owned by this fleet")
		}
		return true, nil
	}
	if target.kind != "kubernetes" || !strings.HasPrefix(id, "job.batch/") {
		return false, fmt.Errorf("autoscale: Kubernetes stop target has unexpected id shape")
	}
	name := strings.TrimPrefix(id, "job.batch/")
	stdout, stderr, err := c.runProbe(ctx, target.command, "get", "--namespace", target.namespace, id, "-o=json")
	if err != nil {
		if ctx.Err() == nil && jobTargetMissing(stderr, name) {
			return false, nil
		}
		return false, fmt.Errorf("autoscale: Kubernetes stop ownership probe failed: %w", err)
	}
	var job struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(stdout), &job); err != nil || job.Kind != "Job" ||
		job.Metadata.Name != name ||
		job.Metadata.Namespace != "" && job.Metadata.Namespace != target.namespace ||
		job.Metadata.Labels["app"] != "reactor-worker" || job.Metadata.Labels[fleetLabel] != fleet {
		return false, fmt.Errorf("autoscale: Kubernetes stop target is not owned by this fleet")
	}
	return true, nil
}

func (c *CommandSpawner) jobInventory(ctx context.Context, command, namespace, fleet string) (map[string]workerState, error) {
	stdout, _, err := c.runProbe(ctx, command, "get", "jobs", "--namespace", namespace, "-l", "app=reactor-worker", "-o=json")
	if err != nil {
		return nil, fmt.Errorf("autoscale: Kubernetes worker inventory failed: %w", err)
	}
	var list struct {
		Kind  string `json:"kind"`
		Items []struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(stdout), &list); err != nil || list.Kind != "JobList" {
		return nil, fmt.Errorf("autoscale: Kubernetes worker inventory returned invalid JobList")
	}
	if len(list.Items) > maxInventoryWorkers {
		return nil, fmt.Errorf("autoscale: Kubernetes worker inventory exceeds %d entries", maxInventoryWorkers)
	}
	states := make(map[string]workerState, len(list.Items))
	seen := make(map[string]struct{}, len(list.Items))
	for _, item := range list.Items {
		id := "job.batch/" + item.Metadata.Name
		if !safeWorkerID(id) || item.Kind != "" && item.Kind != "Job" ||
			item.Metadata.Namespace != "" && item.Metadata.Namespace != namespace ||
			item.Metadata.Labels["app"] != "reactor-worker" {
			return nil, fmt.Errorf("autoscale: Kubernetes worker inventory returned invalid Job")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("autoscale: Kubernetes worker inventory returned duplicate Job")
		}
		seen[id] = struct{}{}
		owner := item.Metadata.Labels[fleetLabel]
		if owner == "" {
			return nil, fmt.Errorf("autoscale: unlabelled Reactor Kubernetes Job makes fleet ownership ambiguous")
		}
		if owner != fleet {
			continue
		}
		state := workerLive
		for _, condition := range item.Status.Conditions {
			if condition.Status == "True" && (condition.Type == "Complete" || condition.Type == "Failed") {
				state = workerTerminal
			}
		}
		states[id] = state
	}
	return states, nil
}

func sortedStateIDs(states map[string]workerState) []string {
	ids := make([]string, 0, len(states))
	for id := range states {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
