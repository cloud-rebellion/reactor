// Package knowledge owns the file-backed corpus of references, lessons,
// and post-mortems that the codegen prompt assembler reads on every
// generate call. The corpus grows from use: pre-seeded with public-source
// references on day one, augmented by Claude-written entries via MCP
// tools and post-mortems auto-generated when a workflow lands in DLQ.
//
// Storage is filesystem + git so each entry is a real text file with a
// real commit history. The MCP server, the CLI, and the codegen prompt
// assembler all read through a single Store value to keep the on-disk
// shape canonical.
package knowledge

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Frontmatter is the YAML-shaped header at the top of every entry file.
// Hand-rolled YAML subset (only the fields below) so the package has no
// third-party dependency. New fields go through this type and the
// matching parse/encode functions below.
type Frontmatter struct {
	ID    string `yaml:"id"`
	Topic string `yaml:"topic"`
	// Tenant scopes an entry. EMPTY means global: the seeded playbooks and
	// anything an admin authors estate-wide, readable by every tenant. A
	// non-empty value belongs to that tenant alone. Automatic post-mortems are
	// stamped from the run, which is what keeps one tenant's failure detail
	// (workflow slug, step names, synthesized diagnostics) out of another's view.
	Tenant          string    `yaml:"tenant,omitempty"`
	Title           string    `yaml:"title"`
	CreatedAt       time.Time `yaml:"created_at"`
	CreatedBy       string    `yaml:"created_by"` // seed | claude | operator
	Sources         []string  `yaml:"sources"`
	Tags            []string  `yaml:"tags"`
	Supersedes      []string  `yaml:"supersedes"`
	LastValidatedAt time.Time `yaml:"last_validated_at"`
	Gold            bool      `yaml:"gold"`
	CitationCount   int       `yaml:"citation_count"`
}

// parseFrontmatter reads the leading `---`-fenced YAML block and returns
// the Frontmatter plus the remaining body bytes. Returns an error if the
// fences are missing or malformed.
func parseFrontmatter(src []byte) (Frontmatter, []byte, error) {
	r := bufio.NewReader(strings.NewReader(string(src)))
	first, err := r.ReadString('\n')
	if err != nil {
		return Frontmatter{}, nil, fmt.Errorf("frontmatter: read first line: %w", err)
	}
	if strings.TrimSpace(first) != "---" {
		return Frontmatter{}, nil, errors.New("frontmatter: missing leading --- fence")
	}
	var fmLines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return Frontmatter{}, nil, fmt.Errorf("frontmatter: read: %w", err)
		}
		if strings.TrimSpace(line) == "---" {
			break
		}
		fmLines = append(fmLines, line)
		if err == io.EOF {
			return Frontmatter{}, nil, errors.New("frontmatter: missing trailing --- fence")
		}
	}
	body, _ := io.ReadAll(r)
	fm, err := decodeFrontmatter(strings.Join(fmLines, ""))
	if err != nil {
		return Frontmatter{}, nil, err
	}
	return fm, body, nil
}

// decodeFrontmatter parses the YAML subset Frontmatter uses. Supports
// scalars (string, bool, int, RFC3339 time), and `[a, b, c]` flow-style
// lists. Anything more exotic is rejected so we never silently drop a
// field a future entry adds.
func decodeFrontmatter(s string) (Frontmatter, error) {
	var fm Frontmatter
	for i, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			return Frontmatter{}, fmt.Errorf("frontmatter line %d: missing colon: %q", i+1, line)
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if err := setFrontmatterField(&fm, key, val); err != nil {
			return Frontmatter{}, fmt.Errorf("frontmatter line %d: %w", i+1, err)
		}
	}
	return fm, nil
}

func setFrontmatterField(fm *Frontmatter, key, val string) error {
	switch key {
	case "id":
		fm.ID = unquote(val)
	case "topic":
		fm.Topic = unquote(val)
	case "tenant":
		fm.Tenant = unquote(val)
	case "title":
		fm.Title = unquote(val)
	case "created_by":
		fm.CreatedBy = unquote(val)
	case "created_at":
		t, err := time.Parse(time.RFC3339, unquote(val))
		if err != nil {
			return fmt.Errorf("created_at: %w", err)
		}
		fm.CreatedAt = t
	case "last_validated_at":
		t, err := time.Parse(time.RFC3339, unquote(val))
		if err != nil {
			return fmt.Errorf("last_validated_at: %w", err)
		}
		fm.LastValidatedAt = t
	case "sources":
		fm.Sources = parseList(val)
	case "tags":
		fm.Tags = parseList(val)
	case "supersedes":
		fm.Supersedes = parseList(val)
	case "gold":
		b, err := strconv.ParseBool(unquote(val))
		if err != nil {
			return fmt.Errorf("gold: %w", err)
		}
		fm.Gold = b
	case "citation_count":
		n, err := strconv.Atoi(unquote(val))
		if err != nil {
			return fmt.Errorf("citation_count: %w", err)
		}
		fm.CitationCount = n
	default:
		return fmt.Errorf("unknown frontmatter key %q", key)
	}
	return nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseList accepts `[a, b, c]` flow-style or empty `[]`. Each element
// is unquoted independently so `[ "with: colon", plain ]` works.
func parseList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "[]" || s == "" {
		return nil
	}
	if !(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) {
		return []string{unquote(s)}
	}
	inner := s[1 : len(s)-1]
	if strings.TrimSpace(inner) == "" {
		return nil
	}
	parts := splitListItems(inner)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, unquote(p))
	}
	return out
}

// splitListItems splits a flow-style list body on commas, honouring
// double-quoted strings so commas inside quotes don't split the item.
func splitListItems(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inQuote {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// encodeFrontmatter writes the Frontmatter as the leading `---`-fenced
// block followed by the body. Output order is stable so git diffs stay
// minimal across rewrites.
func encodeFrontmatter(fm Frontmatter, body string) []byte {
	var b strings.Builder
	b.WriteString("---\n")
	writeStringField(&b, "id", fm.ID)
	writeStringField(&b, "topic", fm.Topic)
	writeStringField(&b, "tenant", fm.Tenant)
	writeStringField(&b, "title", fm.Title)
	if !fm.CreatedAt.IsZero() {
		fmt.Fprintf(&b, "created_at: %s\n", fm.CreatedAt.UTC().Format(time.RFC3339))
	}
	writeStringField(&b, "created_by", fm.CreatedBy)
	writeListField(&b, "sources", fm.Sources)
	writeListField(&b, "tags", fm.Tags)
	writeListField(&b, "supersedes", fm.Supersedes)
	if !fm.LastValidatedAt.IsZero() {
		fmt.Fprintf(&b, "last_validated_at: %s\n", fm.LastValidatedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "gold: %t\n", fm.Gold)
	fmt.Fprintf(&b, "citation_count: %d\n", fm.CitationCount)
	b.WriteString("---\n")
	b.WriteString(strings.TrimLeft(body, "\n"))
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func writeStringField(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	fmt.Fprintf(b, "%s: %s\n", key, quoteIfNeeded(val))
}

func writeListField(b *strings.Builder, key string, vals []string) {
	if len(vals) == 0 {
		fmt.Fprintf(b, "%s: []\n", key)
		return
	}
	cp := append([]string(nil), vals...)
	sort.Strings(cp)
	parts := make([]string, len(cp))
	for i, v := range cp {
		parts[i] = quoteIfNeeded(v)
	}
	fmt.Fprintf(b, "%s: [%s]\n", key, strings.Join(parts, ", "))
}

func quoteIfNeeded(s string) string {
	if strings.ContainsAny(s, ":,[]\"#") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
