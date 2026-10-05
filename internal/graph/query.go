package graph

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Graph attributes include workflow-controlled diagnostics such as DLQ
	// error text. Keep BM25 preparation bounded even when the graph contains a
	// large legacy value; the MCP response has a separate projection bound.
	maxGraphSearchAttrBytes = 8 << 10
	maxGraphSearchTextBytes = 64 << 10
)

// scoreNodes ranks nodes by BM25 over (label + flattened attr values)
// against the query string. Returns nodes in descending score order.
//
// Uses the same tokenisation as internal/knowledge/search.go so query
// hits look the same across the corpus and the runtime graph. Pulled
// in-package to avoid the import cycle a shared util would create.
func scoreNodes(nodes map[string]Node, query string) []Node {
	const (
		k1     = 1.5
		b      = 0.75
		labelW = 2.0
	)
	qTokens := tokenize(query)
	if len(qTokens) == 0 {
		return nil
	}

	docs := make(map[string][]string, len(nodes))
	labels := make(map[string][]string, len(nodes))
	df := map[string]int{}
	totalLen := 0
	for id, n := range nodes {
		body := tokenize(flattenAttrs(n.Attrs)) // attr values
		label := tokenize(n.Label + " " + n.Kind)
		docs[id] = body
		labels[id] = label
		totalLen += len(body) + len(label)
		seen := map[string]bool{}
		for _, t := range body {
			if !seen[t] {
				df[t]++
				seen[t] = true
			}
		}
		for _, t := range label {
			if !seen[t] {
				df[t]++
				seen[t] = true
			}
		}
	}
	N := float64(len(nodes))
	avgLen := 1.0
	if N > 0 {
		avgLen = float64(totalLen) / N
		if avgLen == 0 {
			avgLen = 1
		}
	}

	type scored struct {
		node  Node
		score float64
	}
	hits := make([]scored, 0, len(nodes))
	for id, n := range nodes {
		score := 0.0
		bodyTF := termFreq(docs[id])
		labelTF := termFreq(labels[id])
		dl := float64(len(docs[id]) + len(labels[id]))
		for _, q := range qTokens {
			if df[q] == 0 {
				continue
			}
			idf := math.Log(1 + (N-float64(df[q])+0.5)/(float64(df[q])+0.5))
			tf := float64(bodyTF[q]) + float64(labelTF[q])*labelW
			if tf == 0 {
				continue
			}
			norm := tf * (k1 + 1) / (tf + k1*(1-b+b*dl/avgLen))
			score += idf * norm
		}
		if score > 0 {
			hits = append(hits, scored{node: n, score: score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		// scoreNodes iterates a map, so equal-scoring results need an explicit
		// tie-breaker or the MCP graph context changes between identical calls.
		return hits[i].node.ID < hits[j].node.ID
	})
	out := make([]Node, len(hits))
	for i, h := range hits {
		out[i] = h.node
	}
	return out
}

// flattenAttrs concatenates scalar attr values into one searchable stream.
// Nested maps and slices are deliberately skipped: marshaling an imported
// value just to search it can allocate an unbounded temporary and would put
// opaque payloads into the prompt-selection index. The MCP projection has a
// separate, explicit recursive policy for values that are safe to display.
func flattenAttrs(attrs map[string]any) string {
	if len(attrs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		value, ok := scalarSearchText(attrs[k])
		if !ok {
			continue
		}
		value = truncateGraphSearchText(value, maxGraphSearchAttrBytes)
		remaining := maxGraphSearchTextBytes - b.Len() - 1
		if remaining <= 0 {
			break
		}
		value = truncateGraphSearchText(value, remaining)
		if value == "" {
			continue
		}
		b.WriteString(value)
		b.WriteByte(' ')
	}
	return b.String()
}

func scalarSearchText(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case int:
		return strconv.Itoa(v), true
	case int8:
		return strconv.FormatInt(int64(v), 10), true
	case int16:
		return strconv.FormatInt(int64(v), 10), true
	case int32:
		return strconv.FormatInt(int64(v), 10), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint:
		return strconv.FormatUint(uint64(v), 10), true
	case uint8:
		return strconv.FormatUint(uint64(v), 10), true
	case uint16:
		return strconv.FormatUint(uint64(v), 10), true
	case uint32:
		return strconv.FormatUint(uint64(v), 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case float32:
		return strconv.FormatFloat(float64(v), 'g', -1, 32), true
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64), true
	default:
		return "", false
	}
}

func truncateGraphSearchText(value string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(value) <= max {
		return value
	}
	value = strings.ToValidUTF8(value[:max], "�")
	for len(value) > max {
		_, size := utf8.DecodeLastRuneInString(value)
		if size <= 0 || size > len(value) {
			return ""
		}
		value = value[:len(value)-size]
	}
	return value
}

func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur.WriteRune(r)
			continue
		}
		if cur.Len() > 0 {
			tok := cur.String()
			if len(tok) >= 2 && !stopwords[tok] {
				out = append(out, tok)
			}
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		tok := cur.String()
		if len(tok) >= 2 && !stopwords[tok] {
			out = append(out, tok)
		}
	}
	return out
}

func termFreq(ts []string) map[string]int {
	m := make(map[string]int, len(ts))
	for _, t := range ts {
		m[t]++
	}
	return m
}

var stopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true,
	"that": true, "this": true, "from": true, "into": true,
	"are": true, "was": true, "but": true, "not": true, "you": true,
}
