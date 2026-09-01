package knowledge

import (
	"strings"
	"testing"
)

func TestRedactorScrubPreservesDiagnosticAndRemovesSensitiveValues(t *testing.T) {
	t.Parallel()
	token := "tok_" + strings.Repeat("B9", 16)
	in := "Hash returned HTTP 502 for ada@example.com; access_token=" + token
	out := NewRedactor().Scrub(in)
	for _, forbidden := range []string{"ada@example.com", token} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("Scrub leaked %q: %s", forbidden, out)
		}
	}
	if !strings.Contains(out, "Hash returned HTTP 502") {
		t.Fatalf("Scrub removed generic diagnostic: %s", out)
	}
}
