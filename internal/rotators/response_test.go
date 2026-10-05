package rotators

import (
	"strings"
	"testing"
)

func TestReadBoundedProviderResponse(t *testing.T) {
	t.Parallel()

	body, err := readBoundedProviderResponse(strings.NewReader("ok"), 2)
	if err != nil || string(body) != "ok" {
		t.Fatalf("bounded read = %q, err=%v", body, err)
	}
	if _, err := readBoundedProviderResponse(strings.NewReader("too large"), 2); err == nil {
		t.Fatal("oversized provider response was accepted")
	}
	if _, err := readBoundedProviderResponse(strings.NewReader("ok"), 0); err == nil {
		t.Fatal("zero response limit was accepted")
	}
}
