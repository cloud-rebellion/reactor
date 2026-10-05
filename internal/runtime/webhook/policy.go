package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ProviderPinnedByDAG resolves the required verifier shared by dashboard and MCP authoring.
func ProviderPinnedByDAG(dag json.RawMessage) (string, error) {
	var doc struct {
		Triggers []json.RawMessage `json:"triggers"`
	}
	if err := json.Unmarshal(dag, &doc); err != nil {
		return "", fmt.Errorf("parse dag.json: %w", err)
	}
	if strings.TrimSpace(string(dag)) == "null" {
		return "", errors.New("dag.json must be an object")
	}

	pinned := ""
	for i, raw := range doc.Triggers {
		if strings.TrimSpace(string(raw)) == "null" {
			return "", fmt.Errorf("triggers[%d] must be an object", i)
		}
		var trigger struct {
			Kind     string `json:"kind"`
			Provider string `json:"provider"`
		}
		if err := json.Unmarshal(raw, &trigger); err != nil {
			return "", fmt.Errorf("parse triggers[%d]: %w", i, err)
		}
		if trigger.Kind != "webhook" || trigger.Provider == "" {
			continue
		}
		if strings.TrimSpace(trigger.Provider) != trigger.Provider {
			return "", fmt.Errorf("triggers[%d] provider must not contain surrounding whitespace", i)
		}
		if !IsSupportedProvider(trigger.Provider) {
			return "", fmt.Errorf("triggers[%d] uses unsupported webhook provider %q", i, trigger.Provider)
		}
		if pinned != "" && pinned != trigger.Provider {
			return "", fmt.Errorf("conflicting webhook providers %q and %q", pinned, trigger.Provider)
		}
		pinned = trigger.Provider
	}
	return pinned, nil
}
