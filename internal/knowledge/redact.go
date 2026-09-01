package knowledge

import (
	"fmt"
	"regexp"
)

// Redactor scans entry bodies for likely PII / secret patterns. Used as
// a guard at every Add boundary so a Claude-written post-mortem from a
// run that processed customer data can't leak email addresses or bearer
// tokens into a corpus that operators routinely commit + share.
//
// Returns the patterns matched (rule + sample) so the caller can decide
// whether to scrub, edit, or refuse. The default Store policy is refuse.
type Redactor struct {
	rules []redactRule
}

type redactRule struct {
	name    string
	re      *regexp.Regexp
	example string
}

// NewRedactor builds the default ruleset. Patterns are intentionally
// strict; false positives cost an operator one supersede call but a
// false negative costs a leak.
func NewRedactor() *Redactor {
	return &Redactor{rules: []redactRule{
		{
			name:    "email",
			re:      regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b`),
			example: "user@example.com",
		},
		{
			name:    "jwt",
			re:      regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
			example: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIi...",
		},
		{
			name:    "bearer",
			re:      regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9_\-\.~+/=]{20,}\b`),
			example: "Bearer abc123...",
		},
		{
			name:    "api-key-prefix",
			re:      regexp.MustCompile(`\b(?:sk_live|sk_test|pk_live|rk_live|whsec|xoxb|xoxp|ghp|gho|ghu|github_pat|AKIA|ASIA)_?[A-Za-z0-9_\-]{16,}\b`),
			example: "sk_live_abc...",
		},
		{
			name:    "keyed-credential",
			re:      regexp.MustCompile(`(?i)\b(?:access[_-]?token|refresh[_-]?token|api[_-]?key|authorization|password|secret)\s*[:=]\s*["']?[A-Za-z0-9_\-.~+/=]{8,}["']?`),
			example: "access_token=abc123...",
		},
		{
			name:    "long-hex-key",
			re:      regexp.MustCompile(`\b[a-fA-F0-9]{40,}\b`),
			example: "deadbeef... (40+ hex chars)",
		},
		{
			name:    "phone-e164",
			re:      regexp.MustCompile(`\+\d{8,15}\b`),
			example: "+46701234567",
		},
		{
			name:    "iban",
			re:      regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),
			example: "GB82WEST12345698765432",
		},
	}}
}

// Scrub replaces every likely PII / secret match with a rule-labelled marker.
// Unlike Scan, this is intended for data that must cross an external boundary:
// callers can preserve the surrounding operational diagnostic without sending
// the matched value. Rules are applied sequentially, so overlapping matches
// cannot re-introduce text removed by an earlier rule.
func (r *Redactor) Scrub(body string) string {
	if r == nil {
		return body
	}
	for _, rule := range r.rules {
		body = rule.re.ReplaceAllString(body, "[redacted:"+rule.name+"]")
	}
	return body
}

// RedactionFinding describes one rule hit. Sample is a small slice of
// the matched text (capped) so callers can show a hint without echoing
// the full secret.
type RedactionFinding struct {
	Rule   string
	Sample string
	Offset int
}

// Scan returns every rule hit. Empty result means body is clean.
func (r *Redactor) Scan(body string) []RedactionFinding {
	var out []RedactionFinding
	for _, rule := range r.rules {
		for _, loc := range rule.re.FindAllStringIndex(body, -1) {
			match := body[loc[0]:loc[1]]
			if len(match) > 24 {
				match = match[:24] + "..."
			}
			out = append(out, RedactionFinding{
				Rule:   rule.name,
				Sample: match,
				Offset: loc[0],
			})
		}
	}
	return out
}

// Format returns a human-readable summary of findings, suitable for
// surfacing through an MCP error or CLI message.
func (r *Redactor) Format(findings []RedactionFinding) string {
	if len(findings) == 0 {
		return ""
	}
	out := fmt.Sprintf("knowledge: redactor blocked %d finding(s):", len(findings))
	for _, f := range findings {
		out += fmt.Sprintf("\n  - %s at offset %d: %s", f.Rule, f.Offset, f.Sample)
	}
	return out
}
