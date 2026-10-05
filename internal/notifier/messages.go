package notifier

import (
	"fmt"
	"strings"
	"time"
)

// alertHeadline is the one-line summary used as Slack header /
// email subject. Status emoji + workflow slug + status word.
func alertHeadline(ev Event) string {
	icon := "INFO"
	switch ev.Status {
	case "succeeded":
		icon = "OK"
	case "failed":
		icon = "FAIL"
	case "failed_dlq":
		icon = "DLQ"
	case "test":
		icon = "TEST"
	}
	slug := ev.WorkflowSlug
	if slug == "" {
		slug = "(unknown workflow)"
	}
	return fmt.Sprintf("[Reactor %s] %s: %s", icon, slug, ev.Status)
}

// alertMarkdown renders the Slack section body (Slack mrkdwn).
func alertMarkdown(ev Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*Workflow:* `%s`\n", escapeSlackMrkdwn(ev.WorkflowSlug))
	fmt.Fprintf(&b, "*Run ID:* `%s`\n", escapeSlackMrkdwn(ev.RunID))
	fmt.Fprintf(&b, "*Trigger:* `%s`\n", escapeSlackMrkdwn(ev.TriggerKind))
	fmt.Fprintf(&b, "*Status:* `%s`\n", escapeSlackMrkdwn(ev.Status))
	if !ev.StartedAt.IsZero() {
		fmt.Fprintf(&b, "*Started:* %s\n", ev.StartedAt.UTC().Format(time.RFC3339))
	}
	if !ev.FinishedAt.IsZero() {
		dur := ev.FinishedAt.Sub(ev.StartedAt)
		if dur > 0 {
			fmt.Fprintf(&b, "*Duration:* %s\n", dur.Round(time.Millisecond))
		}
	}
	return b.String()
}

// alertPlainText is the email body + the Slack top-level fallback.
func alertPlainText(ev Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Reactor run %s\n\n", ev.Status)
	fmt.Fprintf(&b, "Workflow: %s\n", ev.WorkflowSlug)
	fmt.Fprintf(&b, "Run ID:   %s\n", ev.RunID)
	fmt.Fprintf(&b, "Trigger:  %s\n", ev.TriggerKind)
	if !ev.StartedAt.IsZero() {
		fmt.Fprintf(&b, "Started:  %s\n", ev.StartedAt.UTC().Format(time.RFC3339))
	}
	if !ev.FinishedAt.IsZero() {
		fmt.Fprintf(&b, "Finished: %s\n", ev.FinishedAt.UTC().Format(time.RFC3339))
		if dur := ev.FinishedAt.Sub(ev.StartedAt); dur > 0 {
			fmt.Fprintf(&b, "Duration: %s\n", dur.Round(time.Millisecond))
		}
	}
	if ev.DashboardURL != "" {
		fmt.Fprintf(&b, "\nOpen run: %s\n", ev.DashboardURL)
	}
	return b.String()
}

func escapeSlackMrkdwn(s string) string {
	r := strings.NewReplacer("`", "'", "<", "&lt;", ">", "&gt;", "&", "&amp;")
	return r.Replace(s)
}
