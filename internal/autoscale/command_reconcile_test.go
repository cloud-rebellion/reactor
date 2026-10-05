package autoscale

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeProbeFixture(t *testing.T, binary, script string) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, binary)
	state := filepath.Join(dir, "state")
	sequence := filepath.Join(dir, "sequence")
	stops := filepath.Join(dir, "stops")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("running\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sequence, []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, state, sequence, stops
}

func setProbeState(t *testing.T, path, state string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(state+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

const dockerProbeScript = `#!/bin/sh
case "$1" in
run)
  case " $* " in *' --label reactor-autoscale-fleet=unit '*) ;; *) exit 4 ;; esac
  IFS= read -r n < "$TEST_SEQUENCE"
  n=$((n + 1))
  printf '%s\n' "$n" > "$TEST_SEQUENCE"
  printf 'container-%s\n' "$n"
  ;;
ps)
  IFS= read -r n < "$TEST_SEQUENCE"
  IFS= read -r state < "$TEST_STATE"
  if [ "$state" != 'missing' ]; then
    i=1
    while [ "$i" -le "$n" ]; do
      if [ ! -f "$TEST_STOPS" ] || ! grep -qx "container-$i" "$TEST_STOPS"; then printf 'container-%s\n' "$i"; fi
      i=$((i + 1))
    done
  fi
  if [ "$TEST_FOREIGN" = '1' ]; then printf 'foreign-1\n'; fi
  if [ "$TEST_LEGACY" = '1' ]; then printf 'legacy-1\n'; fi
  ;;
inspect)
  if [ "$3" = '--format={{json .Config.Labels}}' ]; then
    case "$4" in
      foreign-1) printf '{"reactor-worker":"1","reactor-autoscale-fleet":"other"}\n' ;;
      legacy-1) printf '{"reactor-worker":"1"}\n' ;;
      *) printf '{"reactor-worker":"1","reactor-autoscale-fleet":"%s"}\n' "${TEST_OWNER:-unit}" ;;
    esac
    exit 0
  fi
  IFS= read -r state < "$TEST_STATE"
  case "$state" in
    missing) printf 'Error: No such object: %s\n' "$4" >&2; exit 1 ;;
    error) printf 'Cannot connect to the Docker daemon\n' >&2; exit 1 ;;
    partial) if [ "$4" = 'container-1' ]; then printf 'Error: No such object: %s\n' "$4" >&2; else printf 'Cannot connect to the Docker daemon\n' >&2; fi; exit 1 ;;
    unknown) printf 'mystery\n' ;;
    *) printf '%s\n' "$state" ;;
  esac
  ;;
rm)
  printf 'rm:%s\n' "$2" >> "$TEST_STOPS"
  ;;
stop)
  [ "$2" = '--signal' ] && [ "$3" = 'SIGTERM' ] && [ "$4" = '--time' ] && [ "$5" = '35' ] || exit 4
  printf 'stop:%s\n' "$6" >> "$TEST_STOPS"
  ;;
*) exit 2 ;;
esac
`

func dockerProbeSpawner(t *testing.T) (*CommandSpawner, string, string) {
	t.Helper()
	bin, state, sequence, stops := writeProbeFixture(t, "docker", dockerProbeScript)
	env := append(os.Environ(), "TEST_STATE="+state, "TEST_SEQUENCE="+sequence, "TEST_STOPS="+stops, "REACTOR_AUTOSCALE_FLEET_ID=unit")
	sp := NewCommandSpawner(
		[]string{bin, "run", "-d", "--rm", "--label", "reactor-worker=1",
			"--env", "REACTOR_DB_URL", "--env", "REACTOR_MASTER_KEY",
			"image", "worker", "--root", "/tmp/artifacts", "--concurrency", "1", "--drain-timeout", "30s"},
		[]string{bin, "stop", "--signal", "SIGTERM", "--time", "35", "{id}"}, env, quietLog())
	sp.StopTimeout = 40 * time.Second
	return sp, state, stops
}

func TestDockerReconcileFreesExitedWorkerAndControllerReplacesIt(t *testing.T) {
	sp, state, stops := dockerProbeSpawner(t)
	ctx := context.Background()
	id, err := sp.Spawn(ctx)
	if err != nil || id != "container-1" {
		t.Fatalf("initial spawn = %q, %v", id, err)
	}
	if err := sp.Reconcile(ctx); err != nil || sp.Running() != 1 {
		t.Fatalf("running worker probe = %v; count = %d", err, sp.Running())
	}
	setProbeState(t, state, "exited")
	ctrl := New(Config{Max: 1, QueuePerWorker: 1, ScaleUpCooldown: time.Second}, sp, &fakeDemand{queued: 1}, quietLog())
	ctrl.lastScaleUp = time.Now().Add(-time.Hour)
	ctrl.tick(ctx)
	if got := sp.IDs(); len(got) != 1 || got[0] != "container-2" {
		t.Fatalf("exited worker should be replaced within Max=1, ids = %v", got)
	}
	data, err := os.ReadFile(stops)
	if err != nil || strings.TrimSpace(string(data)) != "rm:container-1" {
		t.Fatalf("terminal container cleanup = %q, %v", data, err)
	}
}

func TestDockerReconcileRetainsSlotsOnProbeFailureThenRecoversMissingWorker(t *testing.T) {
	sp, state, _ := dockerProbeSpawner(t)
	ctx := context.Background()
	if _, err := sp.Spawn(ctx); err != nil {
		t.Fatal(err)
	}
	ctrl := New(Config{Max: 2, QueuePerWorker: 1, ScaleUpCooldown: time.Second}, sp, &fakeDemand{queued: 2}, quietLog())
	ctrl.lastScaleUp = time.Now().Add(-time.Hour)
	setProbeState(t, state, "error")
	ctrl.tick(ctx)
	if got := sp.IDs(); len(got) != 1 || got[0] != "container-1" {
		t.Fatalf("daemon error must hold all scaling, ids = %v", got)
	}
	setProbeState(t, state, "missing")
	ctrl.tick(ctx)
	if got := sp.IDs(); len(got) != 1 || got[0] != "container-2" {
		t.Fatalf("confirmed missing container should free slot and restart, ids = %v", got)
	}
}

func TestDockerReconcileDoesNotPartiallyReleaseSlotsOnProbeFailure(t *testing.T) {
	sp, state, _ := dockerProbeSpawner(t)
	ctx := context.Background()
	for range 2 {
		if _, err := sp.Spawn(ctx); err != nil {
			t.Fatal(err)
		}
	}
	setProbeState(t, state, "partial")
	if err := sp.Reconcile(ctx); err == nil {
		t.Fatal("expected the second probe to fail")
	}
	if got := sp.IDs(); len(got) != 2 || got[0] != "container-1" || got[1] != "container-2" {
		t.Fatalf("partial probe failure released capacity: %v", got)
	}
}

func TestDockerReconcileAdoptsPreviousControllerWorkersBeforeScaling(t *testing.T) {
	first, _, _ := dockerProbeSpawner(t)
	if id, err := first.Spawn(context.Background()); err != nil || id != "container-1" {
		t.Fatalf("first controller spawn = %q, %v", id, err)
	}
	restarted := NewCommandSpawner(first.SpawnArgv, first.StopArgv, first.Env, quietLog())
	ctrl := New(Config{Min: 1, Max: 1, QueuePerWorker: 1, ScaleUpCooldown: time.Second}, restarted, &fakeDemand{queued: 1}, quietLog())
	ctrl.lastScaleUp = time.Now().Add(-time.Hour)
	ctrl.tick(context.Background())
	if got := restarted.IDs(); len(got) != 1 || got[0] != "container-1" {
		t.Fatalf("restarted controller should adopt, not replace, prior worker: %v", got)
	}
	if got := first.IDs(); len(got) != 1 || got[0] != "container-1" {
		t.Fatalf("new controller changed old in-memory handle: %v", got)
	}
}

func TestDockerReconcileIgnoresForeignFleetAndStopsOnlyItsOwn(t *testing.T) {
	sp, _, stops := dockerProbeSpawner(t)
	sp.Env = append(sp.Env, "TEST_FOREIGN=1")
	ctrl := New(Config{Max: 1, QueuePerWorker: 1, ScaleUpCooldown: time.Second}, sp, &fakeDemand{queued: 1}, quietLog())
	ctrl.lastScaleUp = time.Now().Add(-time.Hour)
	ctrl.tick(context.Background())
	if got := sp.IDs(); len(got) != 1 || got[0] != "container-1" {
		t.Fatalf("foreign fleet must not be adopted or block own capacity: %v", got)
	}
	sp.StopAll(context.Background())
	data, err := os.ReadFile(stops)
	if err != nil || strings.TrimSpace(string(data)) != "stop:container-1" {
		t.Fatalf("stop affected a foreign worker: %q, %v", data, err)
	}
}

func TestDockerReconcileHoldsAmbiguousLegacyWorker(t *testing.T) {
	sp, _, _ := dockerProbeSpawner(t)
	sp.Env = append(sp.Env, "TEST_LEGACY=1")
	if err := sp.Reconcile(context.Background()); err == nil {
		t.Fatal("unlabelled legacy worker must hold scaling")
	}
	ctrl := New(Config{Max: 1, QueuePerWorker: 1, ScaleUpCooldown: time.Second}, sp, &fakeDemand{queued: 1}, quietLog())
	ctrl.lastScaleUp = time.Now().Add(-time.Hour)
	ctrl.tick(context.Background())
	if sp.Running() != 0 {
		t.Fatalf("ambiguous legacy fleet permitted spawn: %v", sp.IDs())
	}
}

func TestDockerStopRefusesWorkerWhoseOwnershipChanged(t *testing.T) {
	sp, _, stops := dockerProbeSpawner(t)
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sp.Env = append(sp.Env, "TEST_OWNER=other")
	if err := sp.Stop(context.Background(), id); err == nil {
		t.Fatal("stop must refuse a worker now labelled as another fleet")
	}
	if sp.Running() != 1 {
		t.Fatalf("ownership failure released tracked slot: %v", sp.IDs())
	}
	if _, err := os.Stat(stops); !os.IsNotExist(err) {
		t.Fatalf("foreign worker stop command ran: %v", err)
	}
}

func TestDockerSpawnerUsesConfiguredEnvForFleetID(t *testing.T) {
	t.Setenv(fleetEnv, "other")
	sp, _, _ := dockerProbeSpawner(t)
	if id, err := sp.Spawn(context.Background()); err != nil || id != "container-1" {
		t.Fatalf("configured CLI env fleet ID should take precedence: %q, %v", id, err)
	}
	if err := sp.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDockerSpawnerRejectsManagedLabelOverrides(t *testing.T) {
	for _, options := range [][]string{
		{"--label", "reactor-worker=0"},
		{"--label=reactor-autoscale-fleet=other"},
		{"--label-file=worker-labels.txt"},
	} {
		t.Run(strings.Join(options, "_"), func(t *testing.T) {
			sp, _, _ := dockerProbeSpawner(t)
			index := len(sp.SpawnArgv) - 12
			sp.SpawnArgv = append(append(append([]string{}, sp.SpawnArgv[:index]...), options...), sp.SpawnArgv[index:]...)
			if _, err := sp.Spawn(context.Background()); err == nil || sp.Running() != 0 {
				t.Fatalf("managed label override accepted: %v; ids=%v", err, sp.IDs())
			}
		})
	}
}

func TestDockerPresetShapeDriftHoldsInventoryAndSpawn(t *testing.T) {
	sp, _, _ := dockerProbeSpawner(t)
	sp.SpawnArgv[len(sp.SpawnArgv)-7] = "wrong-command"
	if err := sp.Reconcile(context.Background()); err == nil {
		t.Fatal("preset drift must not silently downgrade to an untracked custom spawner")
	}
	if _, err := sp.Spawn(context.Background()); err == nil || sp.Running() != 0 {
		t.Fatalf("preset drift permitted spawn: %v; ids=%v", err, sp.IDs())
	}
}

func TestDockerPresetRejectsStopGraceShorterThanWorkerDrain(t *testing.T) {
	sp, _, _ := dockerProbeSpawner(t)
	sp.StopArgv[5] = "10" // worker requires 30s to drain.
	if err := sp.Reconcile(context.Background()); err == nil {
		t.Fatal("short Docker stop grace must disable fleet reconciliation")
	}
	if _, err := sp.Spawn(context.Background()); err == nil || sp.Running() != 0 {
		t.Fatalf("short Docker stop grace permitted spawn: %v; ids=%v", err, sp.IDs())
	}
}

func TestDetachedSpawnerRequiresStableFleetID(t *testing.T) {
	sp, _, _ := dockerProbeSpawner(t)
	var withoutFleet []string
	for _, entry := range sp.Env {
		if !strings.HasPrefix(entry, fleetEnv+"=") {
			withoutFleet = append(withoutFleet, entry)
		}
	}
	sp.Env = withoutFleet
	if err := sp.Reconcile(context.Background()); err == nil {
		t.Fatal("inventory without fleet ID should fail closed")
	}
	if _, err := sp.Spawn(context.Background()); err == nil || sp.Running() != 0 {
		t.Fatalf("spawn without fleet ID = %v; tracked = %v", err, sp.IDs())
	}
}

const kubectlProbeScript = `#!/bin/sh
case "$1" in
create)
  if ! grep -q 'reactor-autoscale-fleet: "unit"' ; then exit 4; fi
  printf 'job.batch/reactor-worker-1\n'
  ;;
get)
  IFS= read -r state < "$TEST_STATE"
  if [ "$2" = 'jobs' ]; then
    case "$state" in
      error) printf 'Error from server (Forbidden): jobs.batch is forbidden\n' >&2; exit 1 ;;
      namespace-missing) printf 'Error from server (NotFound): namespaces "tenant" not found\n' >&2; exit 1 ;;
      invalid) printf 'not json\n'; exit 0 ;;
      wrong) printf '{"kind":"PodList","items":[]}\n'; exit 0 ;;
      missing) printf '{"kind":"JobList","items":[]}\n'; exit 0 ;;
      foreign) printf '{"kind":"JobList","items":[{"kind":"Job","metadata":{"name":"reactor-worker-1","namespace":"tenant","labels":{"app":"reactor-worker","reactor-autoscale-fleet":"unit"}}},{"kind":"Job","metadata":{"name":"other-worker","namespace":"tenant","labels":{"app":"reactor-worker","reactor-autoscale-fleet":"other"}}}]}\n'; exit 0 ;;
      legacy) printf '{"kind":"JobList","items":[{"kind":"Job","metadata":{"name":"reactor-worker-1","namespace":"tenant","labels":{"app":"reactor-worker"}}}]}\n'; exit 0 ;;
    esac
    case "$state" in
      complete) condition='{"type":"Complete","status":"True"}' ;;
      failed) condition='{"type":"Failed","status":"True"}' ;;
      *) condition='' ;;
    esac
    printf '{"kind":"JobList","items":[{"kind":"Job","metadata":{"name":"reactor-worker-1","namespace":"tenant","labels":{"app":"reactor-worker","reactor-autoscale-fleet":"unit"}},"status":{"conditions":[%s]}}]}\n' "$condition"
    exit 0
  fi
  case "$state" in
    missing) printf 'Error from server (NotFound): jobs.batch "reactor-worker-1" not found\n' >&2; exit 1 ;;
    error) printf 'Error from server (Forbidden): jobs.batch is forbidden\n' >&2; exit 1 ;;
    namespace-missing) printf 'Error from server (NotFound): namespaces "tenant" not found\n' >&2; exit 1 ;;
    invalid) printf 'not json\n' ;;
    wrong) printf '{"kind":"Job","metadata":{"name":"other","namespace":"tenant"}}\n' ;;
    ownership-mismatch) printf '{"kind":"Job","metadata":{"name":"reactor-worker-1","namespace":"tenant","labels":{"app":"reactor-worker","reactor-autoscale-fleet":"other"}}}\n' ;;
    complete) printf '{"kind":"Job","metadata":{"name":"reactor-worker-1","namespace":"tenant","labels":{"app":"reactor-worker","reactor-autoscale-fleet":"unit"}},"status":{"conditions":[{"type":"Complete","status":"True"}]}}\n' ;;
    failed) printf '{"kind":"Job","metadata":{"name":"reactor-worker-1","namespace":"tenant","labels":{"app":"reactor-worker","reactor-autoscale-fleet":"unit"}},"status":{"conditions":[{"type":"Failed","status":"True"}]}}\n' ;;
    *) printf '{"kind":"Job","metadata":{"name":"reactor-worker-1","namespace":"tenant","labels":{"app":"reactor-worker","reactor-autoscale-fleet":"unit"}},"status":{"conditions":[]}}\n' ;;
  esac
  ;;
delete)
  printf '%s\n' "$5" >> "$TEST_STOPS"
  ;;
*) exit 2 ;;
esac
`

func kubectlProbeSpawner(t *testing.T) (*CommandSpawner, string, string) {
	t.Helper()
	bin, state, sequence, stops := writeProbeFixture(t, "kubectl", kubectlProbeScript)
	env := append(os.Environ(), "TEST_STATE="+state, "TEST_SEQUENCE="+sequence, "TEST_STOPS="+stops, "REACTOR_AUTOSCALE_FLEET_ID=unit")
	sp := NewCommandSpawner(
		[]string{bin, "create", "--namespace", "tenant", "-f", "-", "-o", "name"},
		[]string{bin, "delete", "--namespace", "tenant", "--ignore-not-found", "{id}"}, env, quietLog())
	sp.SpawnStdin = []byte("kind: Job\nmetadata:\n  labels:\n    app: reactor-worker\nspec:\n")
	return sp, state, stops
}

func TestKubernetesReconcileTerminalAndMissingJobs(t *testing.T) {
	for _, stateValue := range []string{"complete", "failed", "missing"} {
		t.Run(stateValue, func(t *testing.T) {
			sp, state, stops := kubectlProbeSpawner(t)
			ctx := context.Background()
			if _, err := sp.Spawn(ctx); err != nil {
				t.Fatal(err)
			}
			if err := sp.Reconcile(ctx); err != nil || sp.Running() != 1 {
				t.Fatalf("active Job probe = %v; count = %d", err, sp.Running())
			}
			setProbeState(t, state, stateValue)
			if err := sp.Reconcile(ctx); err != nil || sp.Running() != 0 {
				t.Fatalf("terminal Job probe = %v; count = %d", err, sp.Running())
			}
			data, err := os.ReadFile(stops)
			if stateValue == "missing" {
				if !os.IsNotExist(err) {
					t.Fatalf("missing Job should need no delete; stop log = %q, %v", data, err)
				}
			} else if err != nil || strings.TrimSpace(string(data)) != "job.batch/reactor-worker-1" {
				t.Fatalf("terminal Job delete = %q, %v", data, err)
			}
		})
	}
}

func TestKubernetesReconcileHoldsAmbiguousFailures(t *testing.T) {
	for _, stateValue := range []string{"error", "namespace-missing", "invalid", "wrong", "legacy"} {
		t.Run(stateValue, func(t *testing.T) {
			sp, state, _ := kubectlProbeSpawner(t)
			if _, err := sp.Spawn(context.Background()); err != nil {
				t.Fatal(err)
			}
			setProbeState(t, state, stateValue)
			if err := sp.Reconcile(context.Background()); err == nil || sp.Running() != 1 {
				t.Fatalf("ambiguous probe = %v; count = %d, want error and retained slot", err, sp.Running())
			}
		})
	}
}

func TestKubernetesReconcileAdoptsAfterRestartAndIgnoresForeignJob(t *testing.T) {
	first, state, stops := kubectlProbeSpawner(t)
	if id, err := first.Spawn(context.Background()); err != nil || id != "job.batch/reactor-worker-1" {
		t.Fatalf("initial Job = %q, %v", id, err)
	}
	setProbeState(t, state, "foreign")
	restarted := NewCommandSpawner(first.SpawnArgv, first.StopArgv, first.Env, quietLog())
	restarted.SpawnStdin = first.SpawnStdin
	if err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := restarted.IDs(); len(got) != 1 || got[0] != "job.batch/reactor-worker-1" {
		t.Fatalf("restart adoption included foreign Job or lost own Job: %v", got)
	}
	restarted.StopAll(context.Background())
	data, err := os.ReadFile(stops)
	if err != nil || strings.TrimSpace(string(data)) != "job.batch/reactor-worker-1" {
		t.Fatalf("stop affected a foreign Job: %q, %v", data, err)
	}
}

func TestKubernetesStopRefusesWorkerWhoseOwnershipChanged(t *testing.T) {
	sp, state, stops := kubectlProbeSpawner(t)
	id, err := sp.Spawn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	setProbeState(t, state, "ownership-mismatch")
	if err := sp.Stop(context.Background(), id); err == nil {
		t.Fatal("stop must refuse a Job now labelled as another fleet")
	}
	if sp.Running() != 1 {
		t.Fatalf("ownership failure released tracked slot: %v", sp.IDs())
	}
	if _, err := os.Stat(stops); !os.IsNotExist(err) {
		t.Fatalf("foreign Job delete command ran: %v", err)
	}
}

type unavailableReconciler struct {
	fakeSpawner
	calls int
}

func (s *unavailableReconciler) Reconcile(context.Context) error {
	s.calls++
	return context.DeadlineExceeded
}

func TestControllerDoesNotBootstrapMinimumWhenWorkerProbeFails(t *testing.T) {
	sp := &unavailableReconciler{}
	ctrl := New(Config{Min: 1, Max: 2, Interval: 10 * time.Millisecond}, sp, &fakeDemand{}, quietLog())
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	ctrl.Run(ctx)
	if sp.calls == 0 || sp.Running() != 0 {
		t.Fatalf("failed startup probe: calls = %d, running = %d; want no spawn", sp.calls, sp.Running())
	}
}
