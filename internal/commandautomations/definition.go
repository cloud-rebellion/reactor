// Package commandautomations validates declarative command plans. It has no
// executor: storing a plan never authorizes or performs its commands.
package commandautomations

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/knowledge"
)

const MaxDefinitionBytes = 128 << 10

type Definition struct {
	Tags  []string `json:"tags,omitempty"`
	Steps []Step   `json:"steps"`
}

type Step struct {
	Name             string   `json:"name"`
	Command          string   `json:"command"`
	Purpose          string   `json:"purpose"`
	ExpectedExitCode int      `json:"expected_exit_code"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	WorkingDir       string   `json:"working_dir,omitempty"`
	CredentialIDs    []string `json:"credential_ids,omitempty"`
}

// StepChange identifies which declarative fields changed between two immutable
// plan versions. It intentionally omits command values; callers can request
// either exact version through the existing tenant-scoped read tool when that
// untrusted data is needed for review.
type StepChange struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// DefinitionDiff is a bounded structural comparison of two plan versions.
// It describes ordering, tags, and step identity/field changes without
// implying that either version is executable.
type DefinitionDiff struct {
	TagsAdded    []string     `json:"tags_added"`
	TagsRemoved  []string     `json:"tags_removed"`
	StepsAdded   []string     `json:"steps_added"`
	StepsRemoved []string     `json:"steps_removed"`
	StepsChanged []StepChange `json:"steps_changed"`
	OrderChanged bool         `json:"order_changed"`
	NoChanges    bool         `json:"no_changes"`
}

// Compare returns a deterministic structural diff for two normalized
// declarative definitions.
func Compare(before, after Definition) DefinitionDiff {
	diff := DefinitionDiff{
		TagsAdded:    setDifference(after.Tags, before.Tags),
		TagsRemoved:  setDifference(before.Tags, after.Tags),
		StepsAdded:   make([]string, 0),
		StepsRemoved: make([]string, 0),
		StepsChanged: make([]StepChange, 0),
		OrderChanged: !reflect.DeepEqual(stepNames(before.Steps), stepNames(after.Steps)),
	}
	beforeSteps, afterSteps := map[string]Step{}, map[string]Step{}
	for _, step := range before.Steps {
		beforeSteps[step.Name] = step
	}
	for _, step := range after.Steps {
		afterSteps[step.Name] = step
	}
	for name := range afterSteps {
		if _, ok := beforeSteps[name]; !ok {
			diff.StepsAdded = append(diff.StepsAdded, name)
			continue
		}
		fields := changedStepFields(beforeSteps[name], afterSteps[name])
		if len(fields) > 0 {
			diff.StepsChanged = append(diff.StepsChanged, StepChange{Name: name, Fields: fields})
		}
	}
	for name := range beforeSteps {
		if _, ok := afterSteps[name]; !ok {
			diff.StepsRemoved = append(diff.StepsRemoved, name)
		}
	}
	sort.Strings(diff.StepsAdded)
	sort.Strings(diff.StepsRemoved)
	sort.Slice(diff.StepsChanged, func(i, j int) bool { return diff.StepsChanged[i].Name < diff.StepsChanged[j].Name })
	diff.NoChanges = len(diff.TagsAdded) == 0 && len(diff.TagsRemoved) == 0 && len(diff.StepsAdded) == 0 && len(diff.StepsRemoved) == 0 && len(diff.StepsChanged) == 0 && !diff.OrderChanged
	return diff
}

func setDifference(left, right []string) []string {
	rightSet := make(map[string]bool, len(right))
	for _, item := range right {
		rightSet[item] = true
	}
	out := make([]string, 0)
	seen := map[string]bool{}
	for _, item := range left {
		if !rightSet[item] && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func stepNames(steps []Step) []string {
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name)
	}
	return names
}

func changedStepFields(before, after Step) []string {
	fields := make([]string, 0, 6)
	if before.Command != after.Command {
		fields = append(fields, "command")
	}
	if before.Purpose != after.Purpose {
		fields = append(fields, "purpose")
	}
	if before.ExpectedExitCode != after.ExpectedExitCode {
		fields = append(fields, "expected_exit_code")
	}
	if before.TimeoutSeconds != after.TimeoutSeconds {
		fields = append(fields, "timeout_seconds")
	}
	if before.WorkingDir != after.WorkingDir {
		fields = append(fields, "working_dir")
	}
	if !reflect.DeepEqual(before.CredentialIDs, after.CredentialIDs) {
		fields = append(fields, "credential_ids")
	}
	return fields
}

var safeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,127}$`)

func ValidName(name string) bool { return safeName.MatchString(name) }

// NormalizeWorkingDir canonicalizes the only working-directory namespace
// understood by the built-in command sandbox. Empty means the sandbox
// default (/workspace); non-empty paths must remain beneath /workspace so a
// plan cannot name a host path or escape through dot-dot traversal. The
// canonical result is used in the immutable definition digest.
func NormalizeWorkingDir(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if !utf8.ValidString(raw) || strings.IndexFunc(raw, func(r rune) bool { return r == 0 || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("working_dir must be valid UTF-8 without control characters")
	}
	if strings.TrimSpace(raw) != raw {
		return "", errors.New("working_dir cannot have leading or trailing whitespace")
	}
	clean := path.Clean(raw)
	if !strings.HasPrefix(clean, "/workspace") || (clean != "/workspace" && !strings.HasPrefix(clean, "/workspace/")) {
		return "", errors.New("working_dir must be an absolute path beneath /workspace")
	}
	return clean, nil
}

// SafeText rejects common inline secrets without reflecting any matched value
// into an error. This is a heuristic guard; operators must still review plans.
func SafeText(text string) error {
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return errors.New("command plan text must be valid UTF-8 without NUL")
	}
	if findings := knowledge.NewRedactor().Scan(text); len(findings) > 0 {
		return fmt.Errorf("command plan contains potentially sensitive text (%s); use credential_ids instead", findings[0].Rule)
	}
	if strings.Contains(text, "PRIVATE KEY-----") {
		return errors.New("command plan cannot contain private keys; use credential_ids instead")
	}
	return nil
}

func Normalize(raw json.RawMessage) (Definition, json.RawMessage, error) {
	var d Definition
	if len(raw) == 0 || len(raw) > MaxDefinitionBytes {
		return d, nil, errors.New("command definition must be 1..131072 bytes")
	}
	// encoding/json applies last-wins semantics to duplicate object keys. A
	// command plan is immutable once stored, so accepting two values for a
	// command, credential reference, or policy field would make the persisted
	// digest depend on which layer happened to parse the input first. Reject
	// duplicate keys at every object depth before decoding the definition.
	if duplicateJSONKey(raw) {
		return d, nil, errors.New("command definition cannot contain duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return d, nil, errors.New("invalid command definition or unknown field")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return d, nil, errors.New("command definition must contain exactly one object")
	}
	if len(d.Steps) == 0 || len(d.Steps) > 64 || len(d.Tags) > 32 {
		return d, nil, errors.New("command definition needs 1..64 steps and at most 32 tags")
	}
	seenTags := map[string]bool{}
	for _, tag := range d.Tags {
		if !ValidName(tag) {
			return d, nil, errors.New("tags must be lowercase slugs of at most 128 bytes")
		}
		if seenTags[tag] {
			return d, nil, errors.New("tags must be unique")
		}
		seenTags[tag] = true
	}
	seen := map[string]bool{}
	for i := range d.Steps {
		step := &d.Steps[i]
		if !ValidName(step.Name) || seen[step.Name] {
			return d, nil, errors.New("step names must be unique lowercase slugs of at most 128 bytes")
		}
		seen[step.Name] = true
		if strings.TrimSpace(step.Command) == "" || len(step.Command) > 8192 ||
			strings.TrimSpace(step.Purpose) == "" || len(step.Purpose) > 1024 || len(step.WorkingDir) > 1024 {
			return d, nil, errors.New("each step needs a command (up to 8192 bytes) and purpose (up to 1024 bytes); working_dir is limited to 1024 bytes")
		}
		workingDir, workingDirErr := NormalizeWorkingDir(step.WorkingDir)
		if workingDirErr != nil {
			return d, nil, workingDirErr
		}
		step.WorkingDir = workingDir
		if step.TimeoutSeconds < 1 || step.TimeoutSeconds > 86400 || step.ExpectedExitCode < 0 || step.ExpectedExitCode > 255 {
			return d, nil, errors.New("timeout_seconds must be 1..86400 and expected_exit_code 0..255")
		}
		if len(step.CredentialIDs) > 32 {
			return d, nil, errors.New("at most 32 credential references per step")
		}
		seenCredentials := map[string]bool{}
		for _, id := range step.CredentialIDs {
			if len(id) == 0 || len(id) > 256 || strings.TrimSpace(id) != id || strings.IndexFunc(id, unicode.IsControl) >= 0 {
				return d, nil, errors.New("invalid credential reference")
			}
			if seenCredentials[id] {
				return d, nil, errors.New("credential references must be unique per step")
			}
			seenCredentials[id] = true
		}
		if err := SafeText(step.Command + "\n" + step.Purpose + "\n" + step.WorkingDir); err != nil {
			return d, nil, err
		}
	}
	normalized, err := json.Marshal(d)
	return d, normalized, err
}

// duplicateJSONKey reports duplicate object members recursively. The standard
// decoder intentionally accepts them, but plans cross several trust
// boundaries (MCP, journal, review, and a future runner), so all boundaries
// must observe the same immutable data.
func duplicateJSONKey(raw []byte) bool {
	return hasDuplicateJSONKey(json.NewDecoder(bytes.NewReader(raw)))
}

func hasDuplicateJSONKey(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return false
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok {
				return false
			}
			if _, exists := seen[name]; exists {
				return true
			}
			seen[name] = struct{}{}
			if hasDuplicateJSONKey(dec) {
				return true
			}
		}
		_, _ = dec.Token()
	case '[':
		for dec.More() {
			if hasDuplicateJSONKey(dec) {
				return true
			}
		}
		_, _ = dec.Token()
	}
	return false
}

// Flow derives every node and edge from the stored step order. There is no
// independently supplied DAG that could disagree with the plan.
func (d Definition) Flow() map[string]any {
	nodes := make([]map[string]any, 0, len(d.Steps))
	edges := make([]map[string]any, 0, len(d.Steps))
	for i, step := range d.Steps {
		node := map[string]any{
			"id": step.Name, "label": step.Name, "kind": "command", "purpose": step.Purpose,
			"command": step.Command, "command_trust": "untrusted",
			"timeout_seconds": step.TimeoutSeconds, "expected_exit_code": step.ExpectedExitCode,
		}
		if step.WorkingDir != "" {
			node["working_dir"] = step.WorkingDir
		}
		if len(step.CredentialIDs) > 0 {
			node["credential_ids"] = append([]string(nil), step.CredentialIDs...)
		}
		nodes = append(nodes, node)
		if i > 0 {
			edges = append(edges, map[string]any{"from": d.Steps[i-1].Name, "to": step.Name})
		}
	}
	return map[string]any{"nodes": nodes, "edges": edges, "executable": false, "content_trust": "untrusted"}
}
