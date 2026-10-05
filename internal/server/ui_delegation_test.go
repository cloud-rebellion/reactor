package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// TestNotificationFormRevealIsDelegated pins the fix for a form that could not
// be completed AT ALL. Its per-kind fieldsets ship hidden and were revealed by an
// inline onchange, which the dashboard's CSP (script-src 'self', no
// 'unsafe-inline') blocks just as it blocks <script> blocks. The Slack URL /
// webhook / SMTP inputs therefore never appeared: a user picked "Slack", saw no
// URL field, submitted, and got "slack webhook URL must start with
// https://hooks.slack.com/" on a form that had also wiped itself.
func TestNotificationFormRevealIsDelegated(t *testing.T) {
	t.Parallel()
	html := notificationsBody(nil, "", nil, "")

	if strings.Contains(html, "onchange=") {
		t.Fatal("the kind select still uses an inline onchange, which the CSP blocks; the fieldsets would stay hidden forever")
	}
	if !strings.Contains(html, `data-reveal-prefix="fields-"`) {
		t.Fatal("the kind select must carry data-reveal-prefix so /assets/ui.js can reveal the matching fieldset")
	}

	// Every option value must have a fieldset the delegated handler can find:
	// id = prefix + value, and the class it scans for.
	for _, kind := range []string{"slack_webhook", "generic_webhook", "email_smtp"} {
		if !strings.Contains(html, fmt.Sprintf(`<option value="%s"`, kind)) {
			t.Fatalf("kind %q is not offered by the select", kind)
		}
		id := fmt.Sprintf(`id="fields-%s"`, kind)
		if !strings.Contains(html, id) {
			t.Fatalf("no fieldset with %s; the reveal targets prefix+value so it would find nothing", id)
		}
	}
	if got := strings.Count(html, "js-reveal-target"); got != 3 {
		t.Fatalf("js-reveal-target count = %d, want 3 (one per kind); the handler hides by this class", got)
	}
}

// TestUIAssetIsServedAndReferenced closes the loop: the delegated handlers only
// work if the file both ships and is loaded. Either half missing silently
// restores the original bugs (dead confirms, uncompletable form).
func TestUIAssetIsServedAndReferenced(t *testing.T) {
	t.Parallel()
	s := &Server{}

	req := httptest.NewRequest(http.MethodGet, "/assets/ui.js", nil)
	rec := httptest.NewRecorder()
	s.assets(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assets/ui.js = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("content-type = %q, want javascript", ct)
	}
	body := rec.Body.String()
	for _, needle := range []string{"data-confirm", "data-reveal-prefix", "js-reveal-target"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("ui.js does not handle %q", needle)
		}
	}

	// And the layout must load it. Every page goes through this one template,
	// so rendering it once covers all of them.
	rec2 := httptest.NewRecorder()
	render(rec2, layout, page{Title: "t", Body: "<p>x</p>"})
	if !strings.Contains(rec2.Body.String(), `src="/assets/ui.js"`) {
		t.Fatal("the layout does not load /assets/ui.js, so no delegated handler runs on any page")
	}
}

// TestDestructiveChannelActionsCarryConfirm guards the confirmations that the
// CSP had silenced on this page specifically.
func TestDestructiveChannelActionsCarryConfirm(t *testing.T) {
	t.Parallel()
	html := notificationsBody([]journal.NotificationChannelMetadata{
		{ID: "ch1", Name: "ops-slack", Kind: "slack_webhook"},
	}, "", nil, "")
	if !strings.Contains(html, `data-confirm="Delete channel `) {
		t.Fatal("delete-channel has no confirmation")
	}
	if strings.Contains(html, "onsubmit=") {
		t.Fatal("delete-channel still uses an inline onsubmit, which never fires")
	}
}
