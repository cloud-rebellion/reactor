package postmortem

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const (
	maxPromptSensitiveValues = 256
	maxPromptSensitiveLength = 4096
	promptRedactionMarker    = "[redacted:run-data]"
)

var (
	// A run-input dictionary removes known signer values if an operator embeds
	// them in workflow or Step identifiers. Raw Step error text is never passed
	// to scrub: it is reduced to a fixed allowlisted diagnostic below.
	labelledNamePattern = regexp.MustCompile(`(?i)(\b(?:name|signer|recipient|customer)(?:[_ .-]?name)?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^,;\r\n]+)`)
	personNamePattern   = regexp.MustCompile(`((?i:\b(?:for|signer|recipient|customer)\s+))\p{Lu}[\p{L}'’-]+(?:[ \t]+\p{Lu}[\p{L}'’-]+){1,3}`)
	httpStatusPatterns  = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bhttp(?:/[0-9](?:\.[0-9])?)?(?:\s+status)?[\s:=]+([1-5][0-9]{2})\b`),
		regexp.MustCompile(`(?i)\bstatus(?:\s+code)?[\s:=]+([1-5][0-9]{2})\b`),
	}
)

// promptSanitizer is deliberately created per run. Besides Reactor's standard
// PII/credential rules, it learns sensitive string values already persisted in
// the run trigger and completed step outputs. It sanitizes the stable identifiers
// included in the prompt without trying to classify every capitalised phrase as
// a person's name.
type promptSanitizer struct {
	redactor *knowledge.Redactor
	values   []string
}

func newPromptSanitizer(run journal.RunInfo, steps []journal.StepRow) promptSanitizer {
	seen := make(map[string]struct{})
	collectPromptSensitiveValues(run.TriggerMeta, seen)
	for _, step := range steps {
		collectPromptSensitiveValues(step.OutputJSONB, seen)
	}

	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	// Replace longer values first so a short nested value cannot leave a suffix
	// of the original sensitive string behind.
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	if len(values) > maxPromptSensitiveValues {
		values = values[:maxPromptSensitiveValues]
	}
	return promptSanitizer{redactor: knowledge.NewRedactor(), values: values}
}

func (s promptSanitizer) scrub(text string) string {
	text = s.redactor.Scrub(text)
	for _, value := range s.values {
		text = strings.ReplaceAll(text, value, promptRedactionMarker)
	}
	text = labelledNamePattern.ReplaceAllString(text, `${1}[redacted:name]`)
	text = personNamePattern.ReplaceAllString(text, `${1}[redacted:name]`)
	return text
}

func collectPromptSensitiveValues(raw json.RawMessage, seen map[string]struct{}) {
	if len(raw) == 0 || len(seen) >= maxPromptSensitiveValues {
		return
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return
	}
	collectPromptJSONValue(value, false, seen)
}

func collectPromptJSONValue(value any, sensitive bool, seen map[string]struct{}) {
	if len(seen) >= maxPromptSensitiveValues {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			collectPromptJSONValue(child, promptSensitiveKey(key), seen)
			if len(seen) >= maxPromptSensitiveValues {
				return
			}
		}
	case []any:
		for _, child := range typed {
			collectPromptJSONValue(child, sensitive, seen)
			if len(seen) >= maxPromptSensitiveValues {
				return
			}
		}
	case string:
		if !sensitive {
			return
		}
		candidate := strings.TrimSpace(typed)
		if candidate == "" || len(candidate) > maxPromptSensitiveLength {
			return
		}
		seen[candidate] = struct{}{}
	}
}

func promptSensitiveKey(key string) bool {
	normalized := strings.ToLower(key)
	normalized = strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(normalized)
	for _, fragment := range []string{
		"name", "title", "company", "email", "phone", "address", "birth", "dob", "ssn",
		"personnummer", "taxid", "iban", "account", "externalid", "token",
		"secret", "password", "authorization", "credential", "apikey",
		"signingurl", "signinglink",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

// summarizeStepError deliberately emits no substring of errorText. A
// redaction heuristic cannot prove that arbitrary provider errors are free of
// customer/document metadata, so external AI receives only fixed categories
// and a syntactically validated HTTP status when one was explicitly labelled.
func summarizeStepError(errorText string) string {
	status := promptHTTPStatus(errorText)
	category := "unknown"
	if status != 0 {
		switch {
		case status == 401:
			category = "authentication"
		case status == 403:
			category = "authorization"
		case status == 409:
			category = "conflict"
		case status == 429:
			category = "rate_limited"
		case status >= 400 && status < 500:
			category = "client"
		case status >= 500:
			category = "upstream"
		default:
			category = "http"
		}
	} else {
		lower := strings.ToLower(errorText)
		switch {
		case strings.Contains(lower, "deadline exceeded"), strings.Contains(lower, "timeout"), strings.Contains(lower, "timed out"):
			category = "timeout"
		case strings.Contains(lower, "rate limit"), strings.Contains(lower, "too many requests"):
			category = "rate_limited"
		case strings.Contains(lower, "connection refused"), strings.Contains(lower, "connection reset"), strings.Contains(lower, "no such host"):
			category = "network"
		case strings.Contains(lower, "context canceled"), strings.Contains(lower, "context cancelled"):
			category = "cancelled"
		case strings.Contains(lower, "invalid"), strings.Contains(lower, "validation"):
			category = "validation"
		}
	}

	if status != 0 {
		return fmt.Sprintf("error_present=true category=%s http_status=%d", category, status)
	}
	return "error_present=true category=" + category
}

func promptHTTPStatus(errorText string) int {
	for _, pattern := range httpStatusPatterns {
		match := pattern.FindStringSubmatch(errorText)
		if len(match) != 2 {
			continue
		}
		status, err := strconv.Atoi(match[1])
		if err == nil && status >= 100 && status <= 599 {
			return status
		}
	}
	return 0
}
