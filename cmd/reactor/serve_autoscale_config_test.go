package main

import (
	"encoding/hex"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/autoscale"
)

func TestParseServeFlagsRejectsUnstoppableCommandAutoscaler(t *testing.T) {
	key := reactorTestMasterKey
	for _, tc := range []struct {
		name    string
		spawn   string
		stop    string
		wantErr string
	}{
		{name: "missing spawn", stop: "nomad job stop {id}", wantErr: "REACTOR_AUTOSCALE_SPAWN_CMD"},
		{name: "missing stop", spawn: "nomad job dispatch reactor-worker", wantErr: "REACTOR_AUTOSCALE_STOP_CMD"},
		{name: "untargeted stop", spawn: "nomad job dispatch reactor-worker", stop: "nomad job stop reactor-worker", wantErr: "must contain {id}"},
		{name: "targeted stop", spawn: "nomad job dispatch reactor-worker", stop: "nomad job stop {id}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "command")
			t.Setenv("REACTOR_AUTOSCALE_SPAWN_CMD", tc.spawn)
			t.Setenv("REACTOR_AUTOSCALE_STOP_CMD", tc.stop)
			_, err := parseServeFlags([]string{
				"--db", "postgres://localhost/reactor",
				"--root", t.TempDir(),
				"--master-key", key,
				"--mode", "distributed", "--autoscale",
			})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid command autoscaler rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parse error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAutoscaleCommandValidationAppliesOnlyWhenActive(t *testing.T) {
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "command")
	t.Setenv("REACTOR_AUTOSCALE_SPAWN_CMD", "")
	t.Setenv("REACTOR_AUTOSCALE_STOP_CMD", "")
	if err := validateAutoscaleCommandConfig(false, true, ""); err != nil {
		t.Fatalf("local mode should ignore distributed autoscaler config: %v", err)
	}
	if err := validateAutoscaleCommandConfig(true, false, ""); err != nil {
		t.Fatalf("disabled autoscaler should ignore custom spawner config: %v", err)
	}
}

func TestEnabledAutoscalerRejectsInvalidWorkerLimitsBeforeServe(t *testing.T) {
	key := reactorTestMasterKey
	flags := []string{"--db", "postgres://localhost/reactor", "--root", t.TempDir(), "--master-key", key, "--mode", "distributed", "--autoscale"}
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "process")
	for _, tc := range []struct {
		name, min, max, queue, wantErr string
	}{
		{name: "valid", min: "1", max: "2", queue: "7"},
		{name: "empty max", min: "0", max: "", queue: "20", wantErr: "REACTOR_AUTOSCALE_MAX"},
		{name: "nonnumeric max", min: "0", max: "four", queue: "20", wantErr: "REACTOR_AUTOSCALE_MAX"},
		{name: "untrusted max value", min: "0", max: "should-remain-private", queue: "20", wantErr: "REACTOR_AUTOSCALE_MAX"},
		{name: "zero max", min: "0", max: "0", queue: "20", wantErr: "REACTOR_AUTOSCALE_MAX"},
		{name: "negative max", min: "0", max: "-1", queue: "20", wantErr: "REACTOR_AUTOSCALE_MAX"},
		{name: "negative min", min: "-1", max: "2", queue: "20", wantErr: "REACTOR_AUTOSCALE_MIN"},
		{name: "min exceeds max", min: "3", max: "2", queue: "20", wantErr: "REACTOR_AUTOSCALE_MIN cannot exceed REACTOR_AUTOSCALE_MAX"},
		{name: "invalid queue", min: "0", max: "2", queue: "many", wantErr: "REACTOR_AUTOSCALE_QUEUE_PER_WORKER"},
		{name: "zero queue", min: "0", max: "2", queue: "0", wantErr: "REACTOR_AUTOSCALE_QUEUE_PER_WORKER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REACTOR_AUTOSCALE_MIN", tc.min)
			t.Setenv("REACTOR_AUTOSCALE_MAX", tc.max)
			t.Setenv("REACTOR_AUTOSCALE_QUEUE_PER_WORKER", tc.queue)
			cfg, err := parseServeFlags(flags)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parse error = %v, want %q", err, tc.wantErr)
				}
				if tc.name == "untrusted max value" && strings.Contains(err.Error(), tc.max) {
					t.Fatal("invalid autoscaler value leaked into startup error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.autoscaleConfig.Min != 1 || cfg.autoscaleConfig.Max != 2 || cfg.autoscaleConfig.QueuePerWorker != 7 {
				t.Fatalf("autoscale config = %+v, want exact configured limits", cfg.autoscaleConfig)
			}
		})
	}
}

func TestInactiveAutoscalerIgnoresWorkerLimits(t *testing.T) {
	key := reactorTestMasterKey
	t.Setenv("REACTOR_AUTOSCALE_MAX", "invalid")
	for _, flags := range [][]string{
		{"--db", "postgres://localhost/reactor", "--root", t.TempDir(), "--master-key", key, "--mode", "distributed"},
		{"--db", "sqlite://" + t.TempDir() + "/reactor.db", "--root", t.TempDir(), "--master-key", key, "--mode", "local", "--autoscale"},
	} {
		if _, err := parseServeFlags(flags); err != nil {
			t.Fatalf("inactive autoscaler rejected unrelated limit: %v", err)
		}
	}
}

func TestProcessAndDockerAutoscalerRejectInvalidConcurrencyBeforeServe(t *testing.T) {
	key := reactorTestMasterKey
	for _, substrate := range []string{"process", "docker"} {
		t.Run(substrate, func(t *testing.T) {
			t.Setenv("REACTOR_AUTOSCALE_SPAWNER", substrate)
			t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
			t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", "reactor-test")
			for _, value := range []string{"", "many", "0", "-1", "65", "should-remain-private"} {
				t.Run("value_"+value, func(t *testing.T) {
					t.Setenv("REACTOR_WORKER_CONCURRENCY", value)
					cfg := &serveConfig{dbURL: "postgres://localhost/reactor", root: t.TempDir(), masterKey: make([]byte, 32)}
					flags := []string{"--db", cfg.dbURL, "--root", cfg.root, "--master-key", key, "--mode", "distributed", "--autoscale"}
					if _, err := parseServeFlags(flags); err == nil || !strings.Contains(err.Error(), "REACTOR_WORKER_CONCURRENCY") ||
						(value == "should-remain-private" && strings.Contains(err.Error(), value)) {
						t.Fatalf("startup error = %v, want safe concurrency rejection", err)
					}
					if _, err := buildSpawner(slog.Default(), cfg); err == nil || !strings.Contains(err.Error(), "REACTOR_WORKER_CONCURRENCY") {
						t.Fatalf("spawner error = %v, want concurrency rejection", err)
					}
				})
			}
		})
	}
}

func TestProcessAndDockerAutoscalerPassExactConcurrency(t *testing.T) {
	for _, substrate := range []string{"process", "docker"} {
		t.Run(substrate, func(t *testing.T) {
			t.Setenv("REACTOR_AUTOSCALE_SPAWNER", substrate)
			t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
			t.Setenv("REACTOR_WORKER_CONCURRENCY", "4")
			cfg := &serveConfig{dbURL: "postgres://localhost/reactor", root: t.TempDir(), masterKey: make([]byte, 32)}
			spawner, err := buildSpawner(slog.Default(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			var argv []string
			switch sp := spawner.(type) {
			case *autoscale.ProcessSpawner:
				argv = sp.Args
			case *autoscale.CommandSpawner:
				argv = sp.SpawnArgv
			default:
				t.Fatalf("unexpected spawner %T", spawner)
			}
			if !strings.Contains(strings.Join(argv, " "), "--concurrency 4") {
				t.Fatalf("spawner argv = %v, want exact concurrency", argv)
			}
		})
	}
}

func TestDetachedAutoscalerRequiresStableFleetIDBeforeServe(t *testing.T) {
	key := reactorTestMasterKey
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "docker")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	flags := []string{"--db", "postgres://localhost/reactor", "--root", t.TempDir(), "--master-key", key, "--mode", "distributed", "--autoscale"}
	for _, id := range []string{"", "Other-Fleet"} {
		t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", id)
		if _, err := parseServeFlags(flags); err == nil || !strings.Contains(err.Error(), "REACTOR_AUTOSCALE_FLEET_ID") {
			t.Fatalf("fleet id %q parse error = %v", id, err)
		}
	}
	t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", "reactor-prod")
	if _, err := parseServeFlags(flags); err != nil {
		t.Fatalf("valid detached fleet rejected: %v", err)
	}
}

func TestAutoscaleWorkerLaunchKeepsCredentialsOutOfArguments(t *testing.T) {
	const dbURL = "postgres://reactor:example-password@db.example/reactor"
	masterKey := strings.Repeat("01234567"+"89abcdef", 2)
	t.Setenv("REACTOR_DB_URL", "postgres://stale@old.example/reactor")
	t.Setenv("REACTOR_MASTER_KEY", strings.Repeat("0", 64))
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	config := &serveConfig{dbURL: dbURL, root: "/var/lib/reactor", masterKey: []byte(masterKey)}
	keyHex := hex.EncodeToString(config.masterKey)
	for _, substrate := range []string{"process", "docker"} {
		t.Run(substrate, func(t *testing.T) {
			t.Setenv("REACTOR_AUTOSCALE_SPAWNER", substrate)
			spawner, err := buildSpawner(slog.Default(), config)
			if err != nil {
				t.Fatal(err)
			}
			var argv, env []string
			switch sp := spawner.(type) {
			case *autoscale.ProcessSpawner:
				argv, env = sp.Args, sp.Env
			case *autoscale.CommandSpawner:
				argv, env = sp.SpawnArgv, sp.Env
				if !strings.Contains(strings.Join(argv, " "), "--env REACTOR_DB_URL --env REACTOR_MASTER_KEY") {
					t.Fatalf("Docker launch does not pass both environment keys: %v", argv)
				}
			default:
				t.Fatalf("unexpected spawner type %T", spawner)
			}
			if strings.Contains(strings.Join(argv, " "), dbURL) || strings.Contains(strings.Join(argv, " "), keyHex) || strings.Contains(strings.Join(argv, " "), "--db") || strings.Contains(strings.Join(argv, " "), "--master-key") {
				t.Fatal("credential value or secret flag remains in worker arguments")
			}
			seenDB, seenKey := 0, 0
			for _, entry := range env {
				if strings.HasPrefix(entry, "REACTOR_DB_URL=") {
					seenDB++
					if entry != "REACTOR_DB_URL="+dbURL {
						t.Fatal("worker inherited a stale database URL")
					}
				}
				if strings.HasPrefix(entry, "REACTOR_MASTER_KEY=") {
					seenKey++
					if entry != "REACTOR_MASTER_KEY="+keyHex {
						t.Fatal("worker inherited a stale vault master key")
					}
				}
			}
			if seenDB != 1 || seenKey != 1 {
				t.Fatalf("worker credential environment entries = %d db, %d key; want one each", seenDB, seenKey)
			}
		})
	}
}

func TestDockerAutoscalerStopAllowsConfiguredWorkerDrain(t *testing.T) {
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "docker")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	cfg := &serveConfig{
		dbURL:        "postgres://localhost/reactor",
		root:         "/var/lib/reactor",
		masterKey:    make([]byte, 32),
		drainTimeout: 45*time.Second + 250*time.Millisecond,
	}
	spawner, err := buildSpawner(slog.Default(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	sp, ok := spawner.(*autoscale.CommandSpawner)
	if !ok {
		t.Fatalf("Docker spawner = %T", spawner)
	}
	if want := []string{"docker", "stop", "--signal", "SIGTERM", "--time", "51", "{id}"}; !reflect.DeepEqual(sp.StopArgv, want) {
		t.Fatalf("Docker stop argv = %v, want %v", sp.StopArgv, want)
	}
	if sp.StopTimeout != 55*time.Second+250*time.Millisecond {
		t.Fatalf("Docker CLI stop timeout = %s, want worker drain plus 10s", sp.StopTimeout)
	}
	if got := sp.SpawnArgv[len(sp.SpawnArgv)-2:]; !reflect.DeepEqual(got, []string{"--drain-timeout", cfg.drainTimeout.String()}) {
		t.Fatalf("worker drain argv = %v", got)
	}
}

func TestKubernetesAutoscalerRequiresSecretAndOmitsDatabaseURL(t *testing.T) {
	key := reactorTestMasterKey
	const dbURL = "postgres://reactor:example-password@db.example/reactor"
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "kubernetes")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	t.Setenv("REACTOR_AUTOSCALE_K8S_DB_SECRET", "")
	flags := []string{"--db", dbURL, "--root", t.TempDir(), "--master-key", key, "--mode", "distributed", "--autoscale"}
	if _, err := parseServeFlags(flags); err == nil || !strings.Contains(err.Error(), "REACTOR_AUTOSCALE_K8S_DB_SECRET") {
		t.Fatalf("missing-secret parse error = %v", err)
	}
	t.Setenv("REACTOR_AUTOSCALE_K8S_DB_SECRET", "reactor-db")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET", "")
	if _, err := parseServeFlags(flags); err == nil || !strings.Contains(err.Error(), "REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET") {
		t.Fatalf("missing-master-key-secret parse error = %v", err)
	}
	t.Setenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET", "reactor-vault")
	t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", "reactor-k8s")
	t.Setenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC", "")
	if _, err := parseServeFlags(flags); err == nil || !strings.Contains(err.Error(), "REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC") {
		t.Fatalf("missing artifact PVC parse error = %v", err)
	}
	t.Setenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC", "reactor-artifacts")
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "")
	if _, err := parseServeFlags(flags); err == nil || !strings.Contains(err.Error(), "REACTOR_WORKER_ARTIFACT_ROOT") {
		t.Fatalf("missing artifact mount path parse error = %v", err)
	}
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "/mnt/reactor-artifacts")
	setKubernetesWorkerResources(t)
	parsed, err := parseServeFlags(flags)
	if err != nil {
		t.Fatalf("configured Kubernetes autoscaler rejected: %v", err)
	}
	if parsed.queueArtifactRoot != "/mnt/reactor-artifacts" {
		t.Fatalf("serving daemon did not retain the worker artifact mount for dispatch admission: %q", parsed.queueArtifactRoot)
	}
	const masterValue = "0123456789abcdef0123456789abcdef"
	config := &serveConfig{dbURL: dbURL, root: "/var/lib/reactor", masterKey: []byte(masterValue)}
	spawner, err := buildSpawner(slog.Default(), config)
	if err != nil {
		t.Fatal(err)
	}
	sp, ok := spawner.(*autoscale.CommandSpawner)
	if !ok {
		t.Fatalf("unexpected spawner type %T", spawner)
	}
	manifest := string(sp.SpawnStdin)
	if strings.Contains(manifest, dbURL) || strings.Contains(manifest, masterValue) || strings.Contains(manifest, "--db") {
		t.Fatal("Kubernetes Job manifest contains a credential value or --db argument")
	}
	for _, want := range []string{
		"name: REACTOR_DB_URL", `name: "reactor-db"`, `key: "db-url"`,
		"name: REACTOR_MASTER_KEY", `name: "reactor-vault"`, `key: "master-key"`,
		"name: REACTOR_WORKER_ARTIFACT_ROOT", `value: "/mnt/reactor-artifacts"`,
		"volumeMounts:", `mountPath: "/mnt/reactor-artifacts"`, "readOnly: true",
		"persistentVolumeClaim:", `claimName: "reactor-artifacts"`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("Kubernetes Job manifest missing %q", want)
		}
	}
	if strings.Count(manifest, "readOnly: true") != 2 {
		t.Fatal("artifact PVC and worker mount must both be read-only")
	}
}

func TestKubernetesAutoscalerRejectsInvalidArtifactMountBeforeBuild(t *testing.T) {
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "kubernetes")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	t.Setenv("REACTOR_AUTOSCALE_K8S_DB_SECRET", "reactor-db")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET", "reactor-vault")
	t.Setenv("REACTOR_AUTOSCALE_FLEET_ID", "reactor-k8s")
	cfg := &serveConfig{root: "/var/lib/reactor", masterKey: make([]byte, 32)}
	for _, tc := range []struct {
		name, pvc, artifactRoot, wantErr string
	}{
		{"missing PVC", "", "/mnt/reactor-artifacts", "REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC"},
		{"invalid PVC", "Bad.Name", "/mnt/reactor-artifacts", "REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC"},
		{"missing path", "reactor-artifacts", "", "REACTOR_WORKER_ARTIFACT_ROOT"},
		{"relative path", "reactor-artifacts", "artifacts", "REACTOR_WORKER_ARTIFACT_ROOT"},
		{"path injection", "reactor-artifacts", "/mnt/artifacts\n  injected: true", "REACTOR_WORKER_ARTIFACT_ROOT"},
		{"shadows state root", "reactor-artifacts", "/var/lib", "REACTOR_WORKER_ARTIFACT_ROOT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC", tc.pvc)
			t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", tc.artifactRoot)
			if err := validateAutoscaleCommandConfig(true, true, cfg.root); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("startup validation = %v, want %s", err, tc.wantErr)
			}
			if _, err := buildSpawner(slog.Default(), cfg); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("spawner build = %v, want %s", err, tc.wantErr)
			}
		})
	}
}

func TestKubernetesAutoscalerHonorsWorkerDrainGrace(t *testing.T) {
	t.Setenv("REACTOR_AUTOSCALE_SPAWNER", "kubernetes")
	t.Setenv("REACTOR_WORKER_IMAGE", "reactor:test")
	t.Setenv("REACTOR_AUTOSCALE_K8S_DB_SECRET", "reactor-db")
	t.Setenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET", "reactor-vault")
	t.Setenv("REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC", "reactor-artifacts")
	t.Setenv("REACTOR_WORKER_ARTIFACT_ROOT", "/mnt/reactor-artifacts")
	setKubernetesWorkerResources(t)
	cfg := &serveConfig{
		root: "/var/lib/reactor", masterKey: make([]byte, 32),
		drainTimeout: 45*time.Second + 250*time.Millisecond,
	}
	spawner, err := buildSpawner(slog.Default(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	sp := spawner.(*autoscale.CommandSpawner)
	if want := []string{"kubectl", "delete", "--namespace", "default", "--ignore-not-found", "--cascade=foreground", "--wait=true", "{id}"}; !reflect.DeepEqual(sp.StopArgv, want) {
		t.Fatalf("Kubernetes stop argv = %v, want foreground deletion of the worker Pod", sp.StopArgv)
	}
	manifest := string(sp.SpawnStdin)
	for _, want := range []string{
		"terminationGracePeriodSeconds: 56",
		`args: ["worker", "--root", "/var/lib/reactor", "--concurrency",`,
		`"--drain-timeout", "45.25s"]`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("Kubernetes Job manifest missing %q", want)
		}
	}
	if sp.StopTimeout != 60*time.Second+250*time.Millisecond {
		t.Fatalf("Kubernetes stop timeout = %s, want worker drain plus 15s", sp.StopTimeout)
	}
	cfg.drainTimeout = time.Duration(1<<63 - 1)
	if _, err := buildSpawner(slog.Default(), cfg); err == nil || !strings.Contains(err.Error(), "drain timeout is too large") {
		t.Fatalf("overflowing drain timeout error = %v", err)
	}
}
