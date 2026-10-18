package webhookpolicy

import (
	"encoding/json"
	"testing"
)

func TestExistingProviderAndLegacyDAGCompatibility(t *testing.T) {
	for _, provider := range []string{"generic", "github", "stripe", "automation-v1", "hash-v1", "flare-v1"} {
		for _, dag := range []string{`{}`, `{"triggers":[{"kind":"cron","spec":"* * * * *"}]}`, `{"triggers":[{"kind":"webhook","provider":"` + provider + `"}]}`} {
			if err := Require(json.RawMessage(dag), provider); err != nil {
				t.Fatalf("provider=%s compatible DAG refused: %v", provider, err)
			}
		}
	}
	if err := Require(json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"generic"}]}`), ""); err != nil {
		t.Fatalf("legacy empty provider lost generic meaning: %v", err)
	}
}
