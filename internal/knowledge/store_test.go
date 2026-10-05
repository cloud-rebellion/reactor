package knowledge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixedNowStr = "2026-05-15T12:00:00Z"

func fixedNow() time.Time {
	t, _ := time.Parse(time.RFC3339, fixedNowStr)
	return t
}

// freshStore returns a Store rooted at t.TempDir() with the clock
// pinned to fixedNow. Restores the clock on test cleanup.
func freshStore(t *testing.T) *Store {
	t.Helper()
	restore := SetClockForTest(fixedNow)
	t.Cleanup(restore)
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSeedingPopulatesEmptyCorpus(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	entries, err := s.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Fatalf("expected at least 8 seed entries, got %d", len(entries))
	}
	// Spot-check a known seed lands.
	if _, err := s.Get(context.Background(), "g_zombie-context"); err != nil {
		t.Fatalf("g_zombie-context not found after seed: %v", err)
	}
}

func TestSeedingIsIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	restore := SetClockForTest(fixedNow)
	defer restore()
	s1, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	count1, _ := s1.List(context.Background(), "")
	s2, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	count2, _ := s2.List(context.Background(), "")
	if len(count1) != len(count2) {
		t.Fatalf("re-seed grew corpus: %d -> %d", len(count1), len(count2))
	}
}

func TestAddRoundtrip(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	in := Entry{
		Frontmatter: Frontmatter{
			Topic:     "testing",
			Title:     "A learned lesson",
			CreatedBy: "operator",
			Tags:      []string{"audit", "qa"},
			Sources:   []string{"https://example.com/ref"},
		},
		Body: "## what we learned\n\nDo not rebuild the index inside a loop.\n",
	}
	out, err := s.Add(context.Background(), in)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if out.Frontmatter.ID == "" {
		t.Fatal("ID should be auto-derived")
	}
	if out.Frontmatter.CreatedAt.IsZero() {
		t.Fatal("CreatedAt should be stamped")
	}
	if !strings.HasPrefix(out.Frontmatter.ID, "t_") {
		t.Fatalf("ID prefix should match topic first letter, got %q", out.Frontmatter.ID)
	}
	got, err := s.Get(context.Background(), out.Frontmatter.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Frontmatter.Title != in.Frontmatter.Title {
		t.Fatalf("title round-trip mismatch: %q vs %q", got.Frontmatter.Title, in.Frontmatter.Title)
	}
}

func TestRedactorBlocksLeakyAdd(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	in := Entry{
		Frontmatter: Frontmatter{Topic: "leaky", Title: "I leaked an email"},
		Body:        "Customer support: customer@example.com filed a complaint.",
	}
	_, err := s.Add(context.Background(), in)
	if err == nil {
		t.Fatal("redactor should block email")
	}
	if _, ok := err.(*ErrRedacted); !ok {
		t.Fatalf("expected ErrRedacted, got %T: %v", err, err)
	}
}

func TestRedactorBlocksApiKey(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	in := Entry{
		Frontmatter: Frontmatter{Topic: "leaky", Title: "I leaked a stripe key"},
		// Split literal so the secret pattern is not contiguous in source (it
		// still concatenates to a real-shaped key at runtime to exercise the
		// redactor); avoids tripping GitHub push protection on the public mirror.
		Body: "API call returned 401 for sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc.",
	}
	if _, err := s.Add(context.Background(), in); err == nil {
		t.Fatal("redactor should block sk_live key")
	}
}

func TestRedactorBlocksSensitiveMetadata(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	for _, tc := range []struct {
		name  string
		front Frontmatter
	}{
		{name: "title email", front: Frontmatter{Topic: "safe", Title: "Owner customer@example.com"}},
		{name: "source token", front: Frontmatter{Topic: "safe", Title: "Reference", Sources: []string{"access_token=" + strings.Repeat("a", 24)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Add(context.Background(), Entry{Frontmatter: tc.front, Body: "safe body"})
			if err == nil {
				t.Fatal("sensitive metadata unexpectedly accepted")
			}
			if _, ok := err.(*ErrRedacted); !ok {
				t.Fatalf("error = %T %v, want ErrRedacted", err, err)
			}
		})
	}
}

func TestAddRejectsControlCharactersInMetadata(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	for _, tc := range []struct {
		name  string
		front Frontmatter
	}{
		{name: "title", front: Frontmatter{Topic: "safe", Title: "line\nforged"}},
		{name: "topic", front: Frontmatter{Topic: "safe/escape", Title: "title"}},
		{name: "tag", front: Frontmatter{Topic: "safe", Title: "title", Tags: []string{"tag\nforged"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Add(context.Background(), Entry{Frontmatter: tc.front, Body: "safe body"}); err == nil {
				t.Fatal("control/path metadata unexpectedly accepted")
			}
		})
	}
}

func TestSearchRanksRelevance(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	hits, err := s.Search(context.Background(), "goroutine context cancellation", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one hit")
	}
	if hits[0].Entry.Frontmatter.ID != "g_zombie-context" {
		t.Fatalf("expected g_zombie-context as top hit, got %q (score=%v)",
			hits[0].Entry.Frontmatter.ID, hits[0].Score)
	}
}

func TestSearchReturnsEmptyOnNoMatch(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	hits, err := s.Search(context.Background(), "xyzzy quux fnord", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected zero hits for nonsense query, got %d", len(hits))
	}
}

func TestAddRejectsOversizedDurableEntry(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	_, err := s.Add(context.Background(), Entry{
		Frontmatter: Frontmatter{Topic: "bounded", Title: "large"},
		Body:        strings.Repeat("x", maxEntryBodyBytes+1),
	})
	if err == nil || !strings.Contains(err.Error(), "body exceeds") {
		t.Fatalf("oversized knowledge body error = %v", err)
	}
}

func TestAddRejectsOversizedSupersedesList(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	supersedes := make([]string, maxEntryListItems+1)
	for i := range supersedes {
		supersedes[i] = fmt.Sprintf("old_%d", i)
	}
	_, err := s.Add(context.Background(), Entry{
		Frontmatter: Frontmatter{Topic: "bounded", Title: "supersession chain", Supersedes: supersedes},
		Body:        "safe body",
	})
	if err == nil || !strings.Contains(err.Error(), "supersedes allow at most") {
		t.Fatalf("oversized supersedes list error = %v", err)
	}
}

func TestListRejectsTopicPathTraversal(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	for _, topic := range []string{"../", "../../tmp"} {
		if _, err := s.List(context.Background(), topic); err == nil {
			t.Fatalf("List(%q) unexpectedly walked outside the knowledge root", topic)
		}
	}
}

func TestListRejectsOversizedDurableFile(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	path := filepath.Join(s.Root, "oversized.md")
	if err := os.WriteFile(path, make([]byte, maxEntryFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized durable file error = %v", err)
	}
}

func TestListRejectsSymlinkEntry(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	target := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(target, []byte("outside corpus"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.Root, "linked.md")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := s.List(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink entry was followed or silently ignored: %v", err)
	}
}

func TestListMetadataReadsFrontmatterWithoutRetainingBody(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	want, err := s.Add(context.Background(), Entry{
		Frontmatter: Frontmatter{Topic: "large", Title: "metadata only"},
		Body:        strings.Repeat("body ", 20<<10),
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := s.ListMetadata(context.Background(), "large")
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) != 1 || metadata[0].ID != want.Frontmatter.ID || metadata[0].Title != "metadata only" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestListMetadataRejectsSymlinkEntry(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	target := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(target, []byte("outside corpus"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.Root, "linked.md")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := s.ListMetadata(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("metadata list followed or silently ignored symlink: %v", err)
	}
}

func TestPromoteGoldRoundtrip(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	in := Entry{
		Frontmatter: Frontmatter{Topic: "ops", Title: "non-gold lesson"},
		Body:        "We learned not to retry indefinitely.",
	}
	added, _ := s.Add(context.Background(), in)
	if added.Frontmatter.Gold {
		t.Fatal("new entries should not be gold by default")
	}
	updated, err := s.PromoteGold(context.Background(), added.Frontmatter.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Frontmatter.Gold {
		t.Fatal("PromoteGold did not flip the flag")
	}
	// And it should persist on re-read.
	reread, _ := s.Get(context.Background(), added.Frontmatter.ID)
	if !reread.Frontmatter.Gold {
		t.Fatal("PromoteGold did not persist to disk")
	}
}

func TestSupersedeChainsOldID(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	original, _ := s.Add(context.Background(), Entry{
		Frontmatter: Frontmatter{Topic: "ops", Title: "v1 of lesson"},
		Body:        "Initial advice.",
	})
	rewrite := Entry{
		Frontmatter: Frontmatter{Topic: "ops", Title: "v2 of lesson"},
		Body:        "Revised advice based on a later run.",
	}
	revised, err := s.Supersede(context.Background(), original.Frontmatter.ID, rewrite, "old advice was wrong")
	if err != nil {
		t.Fatalf("supersede: %v", err)
	}
	found := false
	for _, sid := range revised.Frontmatter.Supersedes {
		if sid == original.Frontmatter.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("supersede chain missing old id; got %v", revised.Frontmatter.Supersedes)
	}
	// Old entry must still exist on disk.
	if _, err := s.Get(context.Background(), original.Frontmatter.ID); err != nil {
		t.Fatal("old entry should survive supersede; git history is the audit")
	}
}

func TestIncrementCitationPersists(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	id := "g_zombie-context"
	if err := s.IncrementCitation(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(context.Background(), id)
	if got.Frontmatter.CitationCount != 1 {
		t.Fatalf("citation count = %d, want 1", got.Frontmatter.CitationCount)
	}
}

func TestListByTopic(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	entries, err := s.List(context.Background(), "goroutines")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 goroutines entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Frontmatter.Topic != "goroutines" {
			t.Fatalf("topic filter leaked %q into goroutines list", e.Frontmatter.Topic)
		}
	}
}

func TestFrontmatterRoundtrip(t *testing.T) {
	t.Parallel()
	in := Frontmatter{
		ID:              "x_123",
		Topic:           "testing",
		Title:           "round-trip with: a colon",
		CreatedAt:       fixedNow(),
		CreatedBy:       "claude",
		Sources:         []string{"https://a.example", "with, comma"},
		Tags:            []string{"a", "b"},
		Supersedes:      []string{},
		LastValidatedAt: fixedNow(),
		Gold:            true,
		CitationCount:   3,
	}
	encoded := encodeFrontmatter(in, "body content\n")
	out, body, err := parseFrontmatter(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.ID != in.ID || out.Topic != in.Topic || out.Title != in.Title {
		t.Fatalf("scalar mismatch: %+v vs %+v", out, in)
	}
	if !out.Gold || out.CitationCount != 3 {
		t.Fatalf("flag/int mismatch: gold=%v cites=%d", out.Gold, out.CitationCount)
	}
	if string(body) != "body content\n" {
		t.Fatalf("body mismatch: %q", body)
	}
	if len(out.Sources) != 2 || out.Sources[1] != "with, comma" {
		t.Fatalf("sources roundtrip lost the comma-quoted item: %v", out.Sources)
	}
}

func TestStoreRoundtripReadsWhatItWrote(t *testing.T) {
	t.Parallel()
	s := freshStore(t)
	in := Entry{
		Frontmatter: Frontmatter{Topic: "rt", Title: "with: colon and []"},
		Body:        "some body\nwith newlines\n",
	}
	added, err := s.Add(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(added.Path, s.Root) {
		t.Fatalf("path not under root: %q", added.Path)
	}
	if filepath.Ext(added.Path) != ".md" {
		t.Fatalf("path missing .md ext: %q", added.Path)
	}
	got, err := s.Get(context.Background(), added.Frontmatter.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != in.Body {
		t.Fatalf("body mismatch on roundtrip: %q vs %q", got.Body, in.Body)
	}
}
