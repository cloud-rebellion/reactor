package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
)

// kubernetesWorkerResources is the operator-declared capacity contract for
// each autoscaled worker Pod. No workload-size defaults are inferred from the
// serving daemon: its CPU count is unrelated to the worker Pod's allocation.
type kubernetesWorkerResources struct {
	concurrency      int64
	cpuRequestMilli  int64
	cpuLimitMilli    int64
	memoryRequestMiB int64
	memoryLimitMiB   int64
}

func parseKubernetesWorkerResources() (kubernetesWorkerResources, error) {
	var resources kubernetesWorkerResources
	var err error
	for _, field := range []struct {
		key      string
		min, max int64
		dest     *int64
	}{
		{"REACTOR_WORKER_CONCURRENCY", 1, 64, &resources.concurrency},
		{"REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", 10, 128000, &resources.cpuRequestMilli},
		{"REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI", 10, 128000, &resources.cpuLimitMilli},
		{"REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB", 128, 1048576, &resources.memoryRequestMiB},
		{"REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB", 128, 1048576, &resources.memoryLimitMiB},
	} {
		*field.dest, err = requiredKubernetesResourceInt(field.key, field.min, field.max)
		if err != nil {
			return kubernetesWorkerResources{}, err
		}
	}
	if resources.cpuRequestMilli > resources.cpuLimitMilli {
		return kubernetesWorkerResources{}, fmt.Errorf("REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI cannot exceed REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI")
	}
	if resources.memoryRequestMiB > resources.memoryLimitMiB {
		return kubernetesWorkerResources{}, fmt.Errorf("REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB cannot exceed REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB")
	}
	// Each workflow subprocess can use up to the supervisor's default memory
	// cap. Leave room for the worker itself as well. The outer Pod limit is
	// essential when the container cannot delegate a per-run cgroup.
	workflowMiB := int64(supervisor.DefaultResourceLimits().MemoryMaxBytes >> 20)
	minimumLimit := resources.concurrency*workflowMiB + 256
	if resources.memoryLimitMiB < minimumLimit {
		return kubernetesWorkerResources{}, fmt.Errorf("REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB must be at least %d MiB for REACTOR_WORKER_CONCURRENCY=%d (workflow budget plus worker headroom)", minimumLimit, resources.concurrency)
	}
	return resources, nil
}

func requiredKubernetesResourceInt(key string, min, max int64) (int64, error) {
	raw, configured := os.LookupEnv(key)
	if !configured {
		return 0, fmt.Errorf("kubernetes autoscaler requires %s", key)
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < min || value > max {
		// Keep a pasted credential or arbitrary content out of startup errors.
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	return value, nil
}
