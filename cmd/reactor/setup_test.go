package main

import (
	"strings"
	"testing"
)

// TestShellSingleQuoteSurvivesDollarSign is the regression test for a
// real bug shipped in Pass C: the setup wizard wrote the argon2id PHC
// hash with %q (Go double-quoted) into reactor.env, which meant
// `source <file>` shell-expanded $argon2id$v=19$... down to =19. The
// daemon then ran with the wrong stored hash and refused every login.
// Fix: shellSingleQuote wraps values in single quotes so shell
// variable expansion never touches them.
func TestShellSingleQuoteSurvivesDollarSign(t *testing.T) {
	t.Parallel()
	in := "$argon2id$v=19$m=65536,t=3,p=2$salt$hash"
	got := shellSingleQuote(in)
	want := `'$argon2id$v=19$m=65536,t=3,p=2$salt$hash'`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestShellSingleQuoteEscapesEmbeddedSingleQuote(t *testing.T) {
	t.Parallel()
	in := "secret'with'quote"
	got := shellSingleQuote(in)
	want := `'secret'\''with'\''quote'`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestShellSingleQuoteEmpty(t *testing.T) {
	t.Parallel()
	if got := shellSingleQuote(""); got != "''" {
		t.Fatalf("empty input got %q, want ''", got)
	}
}

func TestShellSingleQuoteIdempotent(t *testing.T) {
	t.Parallel()
	// A round-trip through any shell-style un-quoter would strip the
	// outer quotes and unescape the inner ones; this test only verifies
	// the surface is well-formed by checking the produced string is
	// balanced and contains the input.
	in := "/var/lib/reactor/state"
	got := shellSingleQuote(in)
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("not balanced: %q", got)
	}
	if !strings.Contains(got, in) {
		t.Fatalf("input not preserved: %q -> %q", in, got)
	}
}

func TestReactorEnvBodyUsesSystemdAssignmentsAndPreservesPHC(t *testing.T) {
	t.Parallel()
	body := reactorEnvBody(
		"sqlite:///var/lib/reactor/reactor.db",
		"admin",
		"$argon2id$v=19$m=65536,t=3,p=2$salt$hash",
		"/var/lib/reactor",
	)
	for _, want := range []string{
		"REACTOR_DB_URL='sqlite:///var/lib/reactor/reactor.db'",
		"REACTOR_BASIC_AUTH_USER='admin'",
		"REACTOR_BASIC_AUTH_PASSWORD_SHA256='$argon2id$v=19$m=65536,t=3,p=2$salt$hash'",
		"REACTOR_ROOT='/var/lib/reactor'",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("environment body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "export REACTOR_") {
		t.Fatalf("environment body uses shell-only export syntax:\n%s", body)
	}
}
