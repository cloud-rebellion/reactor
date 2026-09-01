package main

import "os"

const aiPostmortemEnabledEnv = "REACTOR_AI_POSTMORTEM_ENABLED"

// aiPostmortemEnabled is intentionally fail-closed and separate from the
// Anthropic credential. Possessing an API key may enable operator-requested
// code generation, but it is not consent to send run diagnostics off-host.
func aiPostmortemEnabled() bool {
	return os.Getenv(aiPostmortemEnabledEnv) == "true"
}
