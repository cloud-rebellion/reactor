package supervisor

import (
	"context"
	"strings"
	"testing"
)

func TestSupervisorRequireCgroupFailsClosedBeforeWorkflowStart(t *testing.T) {
	s := &Supervisor{
		BinaryPath: "/bin/true",
		RunID:      "strict-cgroup-test",
		Limits:     ResourceLimits{RequireCgroup: true},
	}
	status, err := s.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "workflow cgroup isolation is required") {
		t.Fatalf("Run status=%q err=%v, want strict cgroup refusal", status, err)
	}
}
