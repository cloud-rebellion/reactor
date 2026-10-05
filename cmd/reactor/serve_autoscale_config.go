package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/bright-interaction/reactor/internal/autoscale"
)

// parseAutoscaleConfig keeps an enabled fleet's declared limits exact. The
// general envIntFirst helper deliberately falls back on parse errors, which is
// unsafe for a HARD worker cap: an invalid explicit maximum must not silently
// become the default of four workers.
func parseAutoscaleConfig() (autoscale.Config, error) {
	min, err := autoscaleInt("REACTOR_AUTOSCALE_MIN", 0)
	if err != nil {
		return autoscale.Config{}, err
	}
	max, err := autoscaleInt("REACTOR_AUTOSCALE_MAX", 4)
	if err != nil {
		return autoscale.Config{}, err
	}
	queuePerWorker, err := autoscaleInt("REACTOR_AUTOSCALE_QUEUE_PER_WORKER", 20)
	if err != nil {
		return autoscale.Config{}, err
	}
	if min < 0 {
		return autoscale.Config{}, fmt.Errorf("REACTOR_AUTOSCALE_MIN must be nonnegative")
	}
	if max < 1 {
		return autoscale.Config{}, fmt.Errorf("REACTOR_AUTOSCALE_MAX must be at least 1")
	}
	if min > max {
		return autoscale.Config{}, fmt.Errorf("REACTOR_AUTOSCALE_MIN cannot exceed REACTOR_AUTOSCALE_MAX")
	}
	if queuePerWorker < 1 {
		return autoscale.Config{}, fmt.Errorf("REACTOR_AUTOSCALE_QUEUE_PER_WORKER must be at least 1")
	}
	return autoscale.Config{Min: min, Max: max, QueuePerWorker: queuePerWorker}, nil
}

func autoscaleInt(key string, fallback int) (int, error) {
	raw, configured := os.LookupEnv(key)
	if !configured {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		// A pasted secret or connection string is still an invalid number.
		// Do not echo its value into startup logs or HTTP health diagnostics.
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return n, nil
}

// parseAutoscaleWorkerConcurrency gives process and Docker workers a bounded
// slot count. Go's scheduler parallelism is a better default than the serving
// host's CPU count when a container has a smaller CPU allocation. A malformed
// explicit value must not silently fall back to a different capacity.
func parseAutoscaleWorkerConcurrency() (int, error) {
	fallback := runtime.GOMAXPROCS(0)
	if fallback > 64 {
		fallback = 64
	}
	value, err := autoscaleInt("REACTOR_WORKER_CONCURRENCY", fallback)
	if err != nil || value < 1 || value > 64 {
		return 0, fmt.Errorf("REACTOR_WORKER_CONCURRENCY must be an integer between 1 and 64")
	}
	return value, nil
}
