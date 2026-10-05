package mcp

import (
	"encoding/json"
	"strings"
)

// mcpCredentialRotationErrorView turns the persisted rotation failure into a
// status receipt. Rotation providers and delivery targets may include URLs,
// response bodies, or other secret-bearing text in their errors; that text is
// useful in server logs but is not safe to return through an AI-facing MCP
// inventory. Keep the field name for compatibility and expose only a stable
// presence marker plus the small set of internal error codes that operators
// can act on without seeing provider details.
func mcpCredentialRotationErrorView(raw string) map[string]any {
	view := map[string]any{
		"present": true,
		"status":  "redacted",
	}
	if code := mcpCredentialRotationErrorCode(raw); code != "" {
		view["code"] = code
	}
	return view
}

func mcpCredentialRotationErrorCode(raw string) string {
	first := strings.TrimSpace(raw)
	if i := strings.IndexByte(first, ':'); i >= 0 {
		first = strings.TrimSpace(first[:i])
	}
	switch first {
	case "unknown_provider", "local_mint_ack_required", "vault_get", "provider_rotate", "empty_value", "vault_rotate", "mark_rotated":
		return first
	default:
		return ""
	}
}

// mcpCredentialAuditDetailView keeps only non-secret rotation metadata. The
// credential audit table deliberately retains target URLs and error details
// for an authenticated operator, but MCP clients do not need those values to
// decide whether a rotation succeeded or needs attention. Unknown fields are
// dropped and URL/error fields are represented by presence booleans.
func mcpCredentialAuditDetailView(raw json.RawMessage) (map[string]any, bool, int) {
	return mcpCredentialAuditDetailViewWithBytes(raw, 0, false)
}

func mcpCredentialAuditDetailViewWithBytes(raw json.RawMessage, durableBytes int, durableTruncated bool) (map[string]any, bool, int) {
	originalBytes := len(raw)
	if durableBytes > 0 {
		originalBytes = durableBytes
	}
	truncated := false
	if durableTruncated || originalBytes > maxMCPCredentialAuditDetail {
		truncated = true
		if len(raw) > maxMCPCredentialAuditDetail {
			raw = raw[:maxMCPCredentialAuditDetail]
		}
	}

	view := map[string]any{"redacted": true}
	var fields map[string]json.RawMessage
	if len(raw) == 0 || duplicateJSONKey(raw) || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return view, truncated, originalBytes
	}

	for _, key := range []string{"provider", "kind", "status", "code"} {
		value, ok := fields[key]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil || strings.TrimSpace(text) == "" || len(text) > 256 || strings.IndexFunc(text, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			continue
		}
		view[key] = strings.TrimSpace(text)
	}
	if _, ok := fields["url"]; ok {
		view["url_present"] = true
	}
	if _, ok := fields["error"]; ok {
		view["error_present"] = true
	}
	return view, truncated, originalBytes
}
