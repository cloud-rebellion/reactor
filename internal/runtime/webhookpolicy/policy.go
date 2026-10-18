// Package webhookpolicy is the shared authoring and execution policy for
// provider-pinned webhook workflows. It has no receiver/dispatcher dependency.
package webhookpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// MaxDAGBytes matches the dashboard's bounded workflow DAG projection.
const MaxDAGBytes = 1 << 20

var ErrPolicy = errors.New("webhook provider policy unavailable or mismatched")

func IsSupportedProvider(provider string) bool {
	switch provider {
	case "automation-v1", "flare-v1", "hash-v1", "generic", "github", "stripe":
		return true
	default:
		return false
	}
}

// ProviderPinnedByDAG reads only exact, unambiguous policy field names. Other
// DAG fields stay compatible with existing workflow authoring formats.
func ProviderPinnedByDAG(dag json.RawMessage) (string, error) {
	if len(dag) > MaxDAGBytes || !utf8.Valid(dag) {
		return "", ErrPolicy
	}
	doc, err := object(dag)
	if err != nil {
		return "", err
	}
	for key := range doc {
		if key != "triggers" && strings.EqualFold(key, "triggers") {
			return "", ErrPolicy
		}
	}
	raw, present := doc["triggers"]
	// Legacy workflows can have no webhook pin.
	if !present {
		return "", nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", ErrPolicy
	}
	var triggers []json.RawMessage
	if json.Unmarshal(raw, &triggers) != nil {
		return "", ErrPolicy
	}
	pinned := ""
	for _, raw := range triggers {
		fields, err := object(raw)
		if err != nil {
			return "", fmt.Errorf("%w: parse triggers", ErrPolicy)
		}
		for key := range fields {
			if key != "kind" && strings.EqualFold(key, "kind") || key != "provider" && strings.EqualFold(key, "provider") {
				return "", ErrPolicy
			}
		}
		var kind string
		if json.Unmarshal(fields["kind"], &kind) != nil || kind == "" || kind != strings.TrimSpace(kind) {
			return "", ErrPolicy
		}
		if kind != "webhook" {
			continue
		}
		providerRaw, present := fields["provider"]
		if !present {
			continue
		}
		var provider string
		if bytes.Equal(bytes.TrimSpace(providerRaw), []byte("null")) || json.Unmarshal(providerRaw, &provider) != nil {
			return "", ErrPolicy
		}
		if provider == "" {
			continue
		}
		if provider != strings.TrimSpace(provider) {
			return "", fmt.Errorf("%w: provider whitespace", ErrPolicy)
		}
		if !IsSupportedProvider(provider) {
			return "", fmt.Errorf("%w: unsupported provider", ErrPolicy)
		}
		if pinned != "" && pinned != provider {
			return "", fmt.Errorf("%w: conflicting webhook providers", ErrPolicy)
		}
		pinned = provider
	}
	return pinned, nil
}

// Require checks the authenticated provider against the exact DAG to execute.
// Empty stored providers retain the historical generic verifier meaning.
func Require(dag json.RawMessage, provider string) error {
	if provider == "" {
		provider = "generic"
	}
	if !IsSupportedProvider(provider) {
		return ErrPolicy
	}
	pinned, err := ProviderPinnedByDAG(dag)
	if err != nil || pinned != "" && pinned != provider {
		return ErrPolicy
	}
	return nil
}

func object(raw []byte) (map[string]json.RawMessage, error) {
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%w: parse JSON object", ErrPolicy)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, fmt.Errorf("%w: unmarshal JSON object", ErrPolicy)
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		token, err := dec.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrPolicy
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, ErrPolicy
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return nil, ErrPolicy
		}
		fields[key] = value
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return nil, ErrPolicy
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("%w: trailing DAG data", ErrPolicy)
	}
	return fields, nil
}
