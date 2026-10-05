package main

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/autoscale"
)

func setKubernetesWorkerResources(t *testing.T) {
	t.Helper()
	t.Setenv("REACTOR_WORKER_CONCURRENCY", "1")
	t.Setenv("REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", "500")
	t.Setenv("REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI", "1000")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB", "512")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB", "1024")
}

func TestKubernetesWorkerResourcesAreExplicitAndBounded(t *testing.T) {
	t.Run("unset cpu limit", func(t *testing.T) {
		setKubernetesWorkerResources(t)
		if err := os.Unsetenv("REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI"); err != nil {
			t.Fatal(err)
		}
		if _, err := parseKubernetesWorkerResources(); err == nil || !strings.Contains(err.Error(), "requires REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI") {
			t.Fatalf("unset CPU limit error = %v", err)
		}
	})
	for _, tc := range []struct {
		name, key, value string
	}{
		{"missing concurrency", "REACTOR_WORKER_CONCURRENCY", ""},
		{"invalid concurrency", "REACTOR_WORKER_CONCURRENCY", "many"},
		{"excess concurrency", "REACTOR_WORKER_CONCURRENCY", "65"},
		{"missing cpu request", "REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", ""},
		{"invalid cpu request", "REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", "private-token"},
		{"zero cpu request", "REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", "0"},
		{"excess cpu limit", "REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI", "128001"},
		{"invalid memory request", "REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB", "1Gi"},
		{"excess memory limit", "REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB", "1048577"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setKubernetesWorkerResources(t)
			t.Setenv(tc.key, tc.value)
			_, err := parseKubernetesWorkerResources()
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("invalid Kubernetes resources error = %v, want %s", err, tc.key)
			}
			if tc.value == "private-token" && strings.Contains(err.Error(), tc.value) {
				t.Fatal("startup error contains untrusted configuration value")
			}
		})
	}
	setKubernetesWorkerResources(t)
	t.Setenv("REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", "2000")
	if _, err := parseKubernetesWorkerResources(); err == nil || !strings.Contains(err.Error(), "CPU_REQUEST_MILLI cannot exceed") {
		t.Fatalf("request over CPU limit error = %v", err)
	}
	t.Setenv("REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", "500")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB", "2048")
	if _, err := parseKubernetesWorkerResources(); err == nil || !strings.Contains(err.Error(), "MEMORY_REQUEST_MIB cannot exceed") {
		t.Fatalf("request over memory limit error = %v", err)
	}
	t.Setenv("REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB", "512")
	t.Setenv("REACTOR_WORKER_CONCURRENCY", "2")
	if _, err := parseKubernetesWorkerResources(); err == nil || !strings.Contains(err.Error(), "must be at least 1280 MiB") {
		t.Fatalf("undersized memory limit error = %v", err)
	}
}

func TestKubernetesAutoscalerRequiresResourceContractBeforeServe(t *testing.T) {
	key := reactorTestMasterKey
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "kubernetes")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	t.Setenv("REACTOR_AUTOSCALE_K8S_DB_SECRET", "reactor-db")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET", "reactor-vault")
	t.Setenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC", "reactor-artifacts")
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "/mnt/reactor-artifacts")
	t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", "reactor-k8s")
	setKubernetesWorkerResources(t)
	t.Setenv("REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", "")
	flags := []string{"--db", "postgres://localhost/reactor", "--root", t.TempDir(), "--master-key", key, "--mode", "distributed", "--autoscale"}
	if _, err := parseServeFlags(flags); err == nil || !strings.Contains(err.Error(), "REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI") {
		t.Fatalf("serve startup should reject missing resource request: %v", err)
	}
}

func TestKubernetesAutoscalerManifestPinsWorkerResourceContract(t *testing.T) {
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "kubernetes")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	t.Setenv("REACTOR_AUTOSCALE_K8S_DB_SECRET", "reactor-db")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET", "reactor-vault")
	t.Setenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC", "reactor-artifacts")
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "/mnt/reactor-artifacts")
	setKubernetesWorkerResources(t)
	t.Setenv("REACTOR_WORKER_CONCURRENCY", "2")
	t.Setenv("REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI", "750")
	t.Setenv("REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI", "1500")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB", "1024")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB", "2048")
	cfg := &serveConfig{root: "/var/lib/reactor", masterKey: make([]byte, 32)}
	spawner, err := buildSpawner(slog.Default(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(spawner.(*autoscale.CommandSpawner).SpawnStdin)
	for _, want := range []string{
		"          resources:\n            requests:\n              cpu: \"750m\"\n              memory: \"1024Mi\"\n            limits:\n              cpu: \"1500m\"\n              memory: \"2048Mi\"",
		`"--concurrency", "2"`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("Kubernetes Job missing resource contract %q", want)
		}
	}
}
