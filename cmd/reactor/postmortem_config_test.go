package main

import (
	"io"
	"log/slog"
	"testing"
)

func TestBuildPostMortemGeneratorRequiresExplicitEgressOptIn(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("ANTHROPIC_API_KEY", "unit-test-anthropic-key")

	// An API key may be present for code generation. That alone must never
	// enable automatic run-diagnostic egress.
	t.Setenv(aiPostmortemEnabledEnv, "")
	if got := buildPostMortemGenerator(log, nil, nil); got != nil {
		t.Fatal("ANTHROPIC_API_KEY alone enabled AI post-mortems")
	}

	// Fail closed on truthy variants; operators must set the documented exact
	// value so a typo cannot silently widen the privacy boundary.
	for _, value := range []string{"1", "TRUE", "yes", "false", " true "} {
		t.Setenv(aiPostmortemEnabledEnv, value)
		if got := buildPostMortemGenerator(log, nil, nil); got != nil {
			t.Fatalf("%s=%q enabled AI post-mortems", aiPostmortemEnabledEnv, value)
		}
	}

	t.Setenv(aiPostmortemEnabledEnv, "true")
	if got := buildPostMortemGenerator(log, nil, nil); got == nil {
		t.Fatal("explicit post-mortem opt-in plus API key did not enable generator")
	}
}

func TestBuildPostMortemGeneratorStillRequiresAnthropicKey(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv(aiPostmortemEnabledEnv, "true")
	t.Setenv("ANTHROPIC_API_KEY", "")
	if got := buildPostMortemGenerator(log, nil, nil); got != nil {
		t.Fatal("post-mortem opt-in without ANTHROPIC_API_KEY enabled generator")
	}
}
