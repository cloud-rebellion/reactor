package server

import (
	"strings"
	"testing"
)

// The advanced cron field is deliberately free-form. Keep its preview out of
// innerHTML so pasted markup is displayed as text rather than parsed as DOM.
func TestCronBuilderEscapesAdvancedPreview(t *testing.T) {
	t.Parallel()
	body, err := assetsFS.ReadFile("assets/cron-builder.js")
	if err != nil {
		t.Fatalf("read embedded cron-builder.js: %v", err)
	}
	src := string(body)
	if strings.Contains(src, "summary.innerHTML") {
		t.Fatal("cron-builder.js inserts operator-entered cron text with innerHTML")
	}
	for _, want := range []string{
		"function renderSummary(label, cron, custom)",
		"summary.textContent = \"\"",
		"customCode.textContent = cron",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("cron-builder.js missing text-safe preview path %q", want)
		}
	}
}
