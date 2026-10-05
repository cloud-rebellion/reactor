package journal

import (
	"crypto/sha256"
	"encoding/hex"
)

// inputSHA256 returns the opaque fingerprint of the exact trigger bytes handed
// to a workflow. The raw bytes are intentionally hashed before the database
// engine can normalise JSON (PostgreSQL JSONB, for example, removes whitespace
// and object-key ordering), so a retry/replay receipt can prove which input was
// dispatched without exposing the input itself.
func inputSHA256(input []byte) string {
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}
