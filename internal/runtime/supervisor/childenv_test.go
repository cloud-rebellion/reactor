package supervisor

import (
	"os"
	"strings"
	"testing"
)

// TestChildEnvWithholdsSecrets is the regression test for the ship-blocker
// where a workflow subprocess inherited the daemon's full environment and
// could read REACTOR_MASTER_KEY + REACTOR_DB_URL to decrypt the whole
// vault. The child must get the system allowlist + input + extra only.
func TestChildEnvWithholdsSecrets(t *testing.T) {
	t.Setenv("REACTOR_MASTER_KEY", "super-secret-key")
	t.Setenv("REACTOR_DB_URL", "postgres://user:pw@db/reactor")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
	t.Setenv("HOME", "/tmp/reactor-state-home")
	t.Setenv("PWD", "/srv/reactor/state")
	t.Setenv("PATH", "/usr/bin:/bin")

	env := childEnv([]byte(`{"x":1}`), []string{"FF_TEST_RECORD=/tmp/rec", "REACTOR_WORKFLOW=0", "HOME=/tmp/override", "REACTOR_MASTER_KEY=override"})

	has := func(prefix string) bool {
		for _, kv := range env {
			if strings.HasPrefix(kv, prefix) {
				return true
			}
		}
		return false
	}

	for _, leaked := range []string{"REACTOR_MASTER_KEY=", "REACTOR_DB_URL=", "ANTHROPIC_API_KEY=", "HOME=", "PWD="} {
		if has(leaked) {
			t.Errorf("child env leaked secret %q", leaked)
		}
	}
	if !has("PATH=") {
		t.Error("child env dropped PATH (allowlisted system var)")
	}
	if !has("REACTOR_INPUT={") {
		t.Error("child env missing REACTOR_INPUT")
	}
	if !has("REACTOR_WORKFLOW=1") {
		t.Error("child env missing REACTOR_WORKFLOW marker")
	}
	countMarker := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "REACTOR_WORKFLOW=") {
			countMarker++
		}
	}
	if countMarker != 1 {
		t.Fatalf("REACTOR_WORKFLOW entries = %d, want exactly one", countMarker)
	}
	if !has("FF_TEST_RECORD=") {
		t.Error("child env missing injected ExtraEnv")
	}
}

func TestChildEnvRejectsInjectedWorkingDirectory(t *testing.T) {
	env := childEnv(nil, []string{"PWD=/srv/reactor/state", "HOME=/srv/reactor/state", "AWS_SECRET_ACCESS_KEY=secret", "REACTOR_RANDOM=secret"})
	for _, kv := range env {
		if strings.HasPrefix(kv, "PWD=") || strings.HasPrefix(kv, "AWS_SECRET_ACCESS_KEY=") || strings.HasPrefix(kv, "REACTOR_RANDOM=") {
			t.Fatalf("childEnv exposed an injected process value: %q", kv)
		}
	}
}

// TestChildEnvOmitsEmptyInput verifies the input var is only added when
// non-empty so the workflow's LookupEnv("REACTOR_INPUT") path stays
// well-defined.
func TestChildEnvOmitsEmptyInput(t *testing.T) {
	env := childEnv(nil, nil)
	for _, kv := range env {
		if strings.HasPrefix(kv, "REACTOR_INPUT=") {
			t.Fatalf("expected no REACTOR_INPUT for empty input, got %q", kv)
		}
	}
	_ = os.Environ
}

func TestChildEnvForWorkDirPinsTemporaryDirectories(t *testing.T) {
	t.Setenv("TMPDIR", "/srv/reactor/shared-tmp")
	t.Setenv("TMP", "/srv/reactor/shared-tmp")
	t.Setenv("TEMP", "/srv/reactor/shared-tmp")
	t.Setenv("PWD", "/srv/reactor/state")

	const workDir = "/tmp/reactor-run-private"
	env := childEnvForWorkDir(nil, nil, workDir)
	want := map[string]string{
		"PWD":    workDir,
		"TMPDIR": workDir,
		"TMP":    workDir,
		"TEMP":   workDir,
	}
	seen := make(map[string]int)
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key, value := kv[:eq], kv[eq+1:]
		if expected, ok := want[key]; ok {
			seen[key]++
			if value != expected {
				t.Errorf("%s = %q, want private work directory %q", key, value, expected)
			}
		}
	}
	for key := range want {
		if seen[key] != 1 {
			t.Errorf("%s entries = %d, want exactly one", key, seen[key])
		}
	}
}
