package server

import (
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestDLQBodyRendersEscapedTriageAndRetry(t *testing.T) {
	rows := []dlqRow{{
		Item: journal.DeadLetterItem{
			ID:        "dlq_1",
			RunID:     "run_1",
			StepName:  "charge",
			ErrorText: `<script>alert("x")</script>`,
			MovedAt:   time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC),
		},
		WorkflowSlug: "payments",
		RunStatus:    "failed_dlq",
	}}
	html := dlqBody(rows, 0, 50, false, true)
	for _, want := range []string{"payments", "/runs/run_1", "/dlq/dlq_1/retry", "retry", "&lt;script&gt;"} {
		if !strings.Contains(html, want) {
			t.Fatalf("DLQ body missing %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, `<script>alert`) {
		t.Fatal("DLQ error was not HTML escaped")
	}
}

func TestDLQBodyEmpty(t *testing.T) {
	if got := dlqBody(nil, 0, 50, false, true); !strings.Contains(got, "dead-letter queue is empty") {
		t.Fatalf("empty DLQ message missing: %s", got)
	}
}

func TestDLQBodyWorkflowLinkKeepsTenantForGlobalViewer(t *testing.T) {
	t.Parallel()
	rows := []dlqRow{{
		Item:         journal.DeadLetterItem{RunID: "run_1", StepName: "send"},
		WorkflowSlug: "payments",
		TenantID:     "acme & sons",
	}}
	global := dlqBody(rows, 0, 50, false, true)
	if !strings.Contains(global, `href="/workflows/payments?tenant=acme+%26+sons"`) {
		t.Fatalf("global DLQ link does not preserve the producing tenant: %s", global)
	}
	member := dlqBody(rows, 0, 50, false, false)
	if strings.Contains(member, "tenant=acme") {
		t.Fatalf("tenant-scoped DLQ link leaked a tenant selector: %s", member)
	}
}
