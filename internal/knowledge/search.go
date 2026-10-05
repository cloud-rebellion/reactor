package knowledge

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// BM25 implementation tuned for the small corpus shape we expect (tens
// to thousands of entries, not millions). Title tokens get a bigger
// weight than body tokens since entry titles are operator- or AI-curated
// hooks; body contains the long-form context.
//
// Stays in-package so callers don't pull in a search lib for a few
// hundred entries. The token shape (lowercase, alphanumeric runs) is
// shared with the graph package's BM25 query so a search hit on the
// corpus and a graph node hit use the same tokenisation.

const (
	bm25K1        = 1.5
	bm25B         = 0.75
	titleWeight   = 3.0
	goldBoost     = 0.5
	staleHalfLife = 0.7 // multiply score by this when entry is past stale window
)

// Hit pairs an entry with its BM25 score. Higher = more relevant.
type Hit struct {
	Entry Entry
	Score float64
}

// rankEntries sorts entries by BM25 score against the query, applying
// gold boost + stale penalty. Returns up to limit hits, descending by
// score. Caller owns the entries slice; this does not mutate it.
func rankEntries(entries []Entry, query string, limit int, staleAfter float64) []Hit {
	if limit <= 0 {
		limit = 10
	}
	qTokens := tokenize(query)
	if len(qTokens) == 0 || len(entries) == 0 {
		return nil
	}

	// Document frequencies for IDF.
	df := map[string]int{}
	docs := make([][]string, len(entries))
	titleDocs := make([][]string, len(entries))
	totalLen := 0
	for i, e := range entries {
		body := tokenize(e.Body)
		title := tokenize(e.Frontmatter.Title)
		docs[i] = body
		titleDocs[i] = title
		totalLen += len(body)
		seen := map[string]bool{}
		for _, t := range body {
			if !seen[t] {
				df[t]++
				seen[t] = true
			}
		}
		for _, t := range title {
			if !seen[t] {
				df[t]++
				seen[t] = true
			}
		}
	}
	avgLen := 1.0
	if len(entries) > 0 {
		avgLen = float64(totalLen) / float64(len(entries))
		if avgLen == 0 {
			avgLen = 1
		}
	}
	N := float64(len(entries))

	hits := make([]Hit, 0, len(entries))
	for i, e := range entries {
		score := scoreEntryTokens(e, docs[i], titleDocs[i], qTokens, df, N, avgLen, staleAfter)
		if score > 0 {
			hits = append(hits, Hit{Entry: e, Score: score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		return hits[i].Score > hits[j].Score
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

// scoreEntryTokens computes one BM25 score from already-tokenized fields.
// Keeping this separate lets the tenant-scoped filesystem search stream the
// corpus in two passes instead of materializing every entry body at once.
func scoreEntryTokens(e Entry, body, title, qTokens []string, df map[string]int, totalDocs float64, avgLen, staleAfter float64) float64 {
	score := 0.0
	bodyTF := termFreq(body)
	titleTF := termFreq(title)
	dl := float64(len(body))
	for _, q := range qTokens {
		n := df[q]
		if n == 0 {
			continue
		}
		idf := math.Log(1 + (totalDocs-float64(n)+0.5)/(float64(n)+0.5))
		tfBody := float64(bodyTF[q])
		tfTitle := float64(titleTF[q]) * titleWeight
		tf := tfBody + tfTitle
		if tf == 0 {
			continue
		}
		norm := tf * (bm25K1 + 1) / (tf + bm25K1*(1-bm25B+bm25B*dl/avgLen))
		score += idf * norm
	}
	if e.Frontmatter.Gold {
		score *= 1 + goldBoost
	}
	if staleAfter > 0 && isStale(e, staleAfter) {
		score *= staleHalfLife
	}
	return score
}

// tokenize lowercases + splits on non-alphanumeric runs. Tiny stopword
// list to keep the inverted index tight.
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

func termFreq(tokens []string) map[string]int {
	m := make(map[string]int, len(tokens))
	for _, t := range tokens {
		m[t]++
	}
	return m
}

var stopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true,
	"that": true, "this": true, "from": true, "into": true,
	"are": true, "was": true, "but": true, "not": true, "you": true,
}

// isStale returns true when the entry's last_validated_at is older than
// staleAfter days. Zero last_validated_at counts as fresh (seed entries
// are minted with the install date).
func isStale(e Entry, staleAfterDays float64) bool {
	if e.Frontmatter.LastValidatedAt.IsZero() {
		return false
	}
	cutoff := nowFn().AddDate(0, 0, -int(staleAfterDays))
	return e.Frontmatter.LastValidatedAt.Before(cutoff)
}
