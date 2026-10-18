package webhook

import (
	"encoding/json"

	"github.com/bright-interaction/reactor/internal/runtime/webhookpolicy"
)

// ProviderPinnedByDAG resolves the required verifier shared by dashboard and MCP authoring.
func ProviderPinnedByDAG(dag json.RawMessage) (string, error) {
	return webhookpolicy.ProviderPinnedByDAG(dag)
}
