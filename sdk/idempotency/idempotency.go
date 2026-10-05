// Package idempotency centralises the idempotency-key derivation that
// every side-effecting Step needs. The codegen prompt's i_step-keys
// entry teaches workflows to call this rather than hand-roll sha256.
package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Key derives a stable hex-encoded SHA-256 over the workflow slug, step
// name, and the canonical-ordered key/value parts. Use this as
// StepOpts.IdempotencyKey on every side-effecting step so a completed step
// can be reused on replay. A provider mutation accepted before its result
// is journaled may still be repeated; this is not provider-side exactly once.
//
//	idem := idempotency.Key("welcome-customer", "send-email",
//	    "customer_id", req.CustomerID, "template", "welcome-v3")
func Key(workflowSlug, stepName string, kv ...string) string {
	if len(kv)%2 != 0 {
		kv = append(kv, "")
	}
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		parts = append(parts, kv[i]+"="+kv[i+1])
	}
	sort.Strings(parts)
	h := sha256.New()
	fmt.Fprintf(h, "%s:%s:%s", workflowSlug, stepName, strings.Join(parts, "&"))
	return hex.EncodeToString(h.Sum(nil))
}

// KeyForPayload is a shortcut when the operator-meaningful identity is
// a single payload field (the common case for webhook-driven workflows).
func KeyForPayload(workflowSlug, stepName, payloadID string) string {
	return Key(workflowSlug, stepName, "id", payloadID)
}
