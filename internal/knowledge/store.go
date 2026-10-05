package knowledge

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

//go:embed seed/*.md
var seedFS embed.FS

// nowFnPtr is the package-level clock, held in an atomic.Pointer so
// SetClockForTest can swap it from parallel tests under -race without
// triggering the detector. Initialised to time.Now in init below.
var nowFnPtr atomic.Pointer[func() time.Time]

func init() {
	def := func() time.Time { return time.Now() }
	nowFnPtr.Store(&def)
}

func nowFn() time.Time {
	return (*nowFnPtr.Load())()
}

// Entry is one corpus item: the parsed frontmatter + the body markdown
// + the on-disk path the body was read from.
type Entry struct {
	Frontmatter Frontmatter
	Body        string
	Path        string
}

// Committer is the git surface the Store calls after every successful
// add / supersede / promote. Mirrors codegen.Committer's signature so
// the same GitCommitter instance can serve both packages.
type Committer interface {
	Commit(ctx context.Context, dir, slug, version string) error
}

// noopCommitter is the default when callers don't pass one. Useful for
// tests + for installations where REACTOR_GIT_BACKED=false.
type noopCommitter struct{}

func (noopCommitter) Commit(_ context.Context, _, _, _ string) error { return nil }

// ErrNotFound is returned when an entry id doesn't resolve to a file.
var ErrNotFound = errors.New("knowledge: entry not found")

// ErrRedacted is returned when an Add or Revise hits the PII redactor.
// Wraps the formatted finding list so callers can surface details.
type ErrRedacted struct {
	Findings []RedactionFinding
	Summary  string
}

func (e *ErrRedacted) Error() string { return e.Summary }

// Store is the knowledge corpus. One instance per process; safe for
// concurrent reads but every write takes the write side of the RWMutex.
type Store struct {
	Root      string    // ~/.reactor/knowledge by convention
	Git       Committer // optional; nil → noopCommitter
	Redactor  *Redactor // optional; nil → NewRedactor()
	StaleDays float64   // 0 → 90 by default

	mu sync.RWMutex
}

const (
	maxEntryBodyBytes = 1 << 20 // 1 MiB per durable knowledge entry
	// Read paths must bound the whole file as well as Add's body. A manually
	// planted or legacy file can otherwise make List/Get allocate an arbitrary
	// amount before frontmatter validation gets a chance to run.
	maxEntryFileBytes  = maxEntryBodyBytes + 64<<10
	maxEntryTitleBytes = 512
	maxEntryTopicBytes = 128
	maxEntryListItems  = 64
	maxEntryListBytes  = 512
)

// New returns a Store rooted at root. Creates root with mode 0700 if
// it doesn't exist. Pre-seeds the corpus on a fresh install by walking
// the embedded seed/ directory.
func New(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("knowledge: root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("knowledge: mkdir root: %w", err)
	}
	s := &Store{Root: root, Git: noopCommitter{}, Redactor: NewRedactor(), StaleDays: 90}
	if err := s.seedIfEmpty(); err != nil {
		return nil, err
	}
	return s, nil
}

// seedIfEmpty walks the embedded seed FS and writes any entries whose
// id isn't already present in Root. Idempotent: re-running on a
// populated corpus is a no-op.
func (s *Store) seedIfEmpty() error {
	return fs.WalkDir(seedFS, "seed", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		raw, err := seedFS.ReadFile(path)
		if err != nil {
			return err
		}
		fm, _, err := parseFrontmatter(raw)
		if err != nil {
			return fmt.Errorf("knowledge: seed %s: %w", path, err)
		}
		dest := filepath.Join(s.Root, fm.Topic, fm.ID+".md")
		if _, err := os.Stat(dest); err == nil {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return err
		}
		// Re-encode so the on-disk shape is canonical and the seed time
		// reflects the install.
		fm.CreatedAt = nowFn().UTC()
		if fm.LastValidatedAt.IsZero() {
			fm.LastValidatedAt = fm.CreatedAt
		}
		_, body, err := parseFrontmatter(raw)
		if err != nil {
			return err
		}
		out := encodeFrontmatter(fm, string(body))
		return os.WriteFile(dest, out, 0o600)
	})
}

// Add validates the entry through the redactor, derives an id if empty,
// stamps timestamps, writes to <Root>/<Topic>/<ID>.md, and commits via
// Git. The caller-passed Frontmatter wins on Title + Topic + Sources +
// Tags + CreatedBy; everything else is overwritten by Add.
func (s *Store) Add(ctx context.Context, e Entry) (Entry, error) {
	if e.Frontmatter.Topic == "" {
		return Entry{}, errors.New("knowledge: topic required")
	}
	if e.Frontmatter.Title == "" {
		return Entry{}, errors.New("knowledge: title required")
	}
	if e.Body == "" {
		return Entry{}, errors.New("knowledge: body required")
	}
	if len(e.Body) > maxEntryBodyBytes {
		return Entry{}, fmt.Errorf("knowledge: body exceeds %d-byte limit", maxEntryBodyBytes)
	}
	if len(e.Frontmatter.Title) > maxEntryTitleBytes {
		return Entry{}, fmt.Errorf("knowledge: title exceeds %d-byte limit", maxEntryTitleBytes)
	}
	if len(e.Frontmatter.Topic) > maxEntryTopicBytes {
		return Entry{}, fmt.Errorf("knowledge: topic exceeds %d-byte limit", maxEntryTopicBytes)
	}
	for name, value := range map[string]string{
		"title": e.Frontmatter.Title, "topic": e.Frontmatter.Topic,
		"tenant": e.Frontmatter.Tenant, "created_by": e.Frontmatter.CreatedBy,
		"id": e.Frontmatter.ID,
	} {
		if err := validateMetadataText(name, value); err != nil {
			return Entry{}, err
		}
	}
	if strings.ContainsAny(e.Frontmatter.Topic, `/\\`) || e.Frontmatter.Topic == "." || e.Frontmatter.Topic == ".." {
		return Entry{}, fmt.Errorf("knowledge: invalid topic %q", e.Frontmatter.Topic)
	}
	if len(e.Frontmatter.Sources) > maxEntryListItems || len(e.Frontmatter.Tags) > maxEntryListItems || len(e.Frontmatter.Supersedes) > maxEntryListItems {
		return Entry{}, fmt.Errorf("knowledge: sources, tags, and supersedes allow at most %d items", maxEntryListItems)
	}
	for _, value := range e.Frontmatter.Sources {
		if len(value) > maxEntryListBytes {
			return Entry{}, fmt.Errorf("knowledge: source item exceeds %d-byte limit", maxEntryListBytes)
		}
		if err := validateMetadataText("source", value); err != nil {
			return Entry{}, err
		}
	}
	for _, value := range e.Frontmatter.Tags {
		if len(value) > maxEntryListBytes {
			return Entry{}, fmt.Errorf("knowledge: tag item exceeds %d-byte limit", maxEntryListBytes)
		}
		if err := validateMetadataText("tag", value); err != nil {
			return Entry{}, err
		}
	}
	for _, value := range e.Frontmatter.Supersedes {
		if err := validateMetadataText("supersedes", value); err != nil {
			return Entry{}, err
		}
	}
	redactor := s.Redactor
	if redactor == nil {
		redactor = NewRedactor()
	}
	var findings []RedactionFinding
	for _, value := range []string{e.Body, e.Frontmatter.Title, e.Frontmatter.Topic, e.Frontmatter.Tenant, e.Frontmatter.CreatedBy, e.Frontmatter.ID} {
		findings = append(findings, redactor.Scan(value)...)
	}
	for _, values := range [][]string{e.Frontmatter.Sources, e.Frontmatter.Tags, e.Frontmatter.Supersedes} {
		for _, value := range values {
			findings = append(findings, redactor.Scan(value)...)
		}
	}
	if len(findings) > 0 {
		return Entry{}, &ErrRedacted{Findings: findings, Summary: redactor.Format(findings)}
	}

	if e.Frontmatter.ID == "" {
		id, err := newID(e.Frontmatter.Topic)
		if err != nil {
			return Entry{}, err
		}
		e.Frontmatter.ID = id
	}
	now := nowFn().UTC()
	e.Frontmatter.CreatedAt = now
	if e.Frontmatter.CreatedBy == "" {
		e.Frontmatter.CreatedBy = "operator"
	}
	if e.Frontmatter.LastValidatedAt.IsZero() {
		e.Frontmatter.LastValidatedAt = now
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Join(s.Root, e.Frontmatter.Topic)
	// Path-traversal guard: Topic is caller-controlled (HTTP + MCP add) and
	// becomes a filesystem path segment. A value like "../../../etc/cron.d"
	// would MkdirAll + WriteFile an attacker-bodied .md outside the knowledge
	// root. Reject anything that resolves outside s.Root.
	if !withinRoot(s.Root, dir) {
		return Entry{}, fmt.Errorf("knowledge: invalid topic %q (escapes the knowledge root)", e.Frontmatter.Topic)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Entry{}, fmt.Errorf("knowledge: mkdir topic: %w", err)
	}
	dest := filepath.Join(dir, e.Frontmatter.ID+".md")
	if !withinRoot(s.Root, dest) {
		return Entry{}, fmt.Errorf("knowledge: invalid id %q (escapes the knowledge root)", e.Frontmatter.ID)
	}
	if _, err := os.Stat(dest); err == nil {
		return Entry{}, fmt.Errorf("knowledge: id %q already exists; use Supersede to replace", e.Frontmatter.ID)
	}
	out := encodeFrontmatter(e.Frontmatter, e.Body)
	if err := os.WriteFile(dest, out, 0o600); err != nil {
		return Entry{}, fmt.Errorf("knowledge: write: %w", err)
	}
	e.Path = dest
	if err := s.commit(ctx, dir, "add: "+e.Frontmatter.ID); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// validateMetadataText keeps frontmatter safe for both YAML encoding and the
// prompt metadata line. Bodies may contain markdown/newlines, but IDs, labels,
// tenant names, topics, tags, and source references must never contain control
// bytes that can forge a new record or create a surprising path.
func validateMetadataText(field, value string) error {
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("knowledge: %s must be valid UTF-8 without control characters", field)
	}
	return nil
}

// withinRoot reports whether path stays inside root after cleaning. It guards
// caller-controlled path segments (knowledge Topic/ID) that use "../" to escape
// the knowledge directory.
func withinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func readEntryFile(path string) ([]byte, error) {
	if _, err := entryFileInfo(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

const maxEntryFrontmatterBytes = 64 << 10

// readEntryFrontmatter validates the same on-disk boundary as readEntryFile
// but reads only a bounded prefix. The prefix is enough to parse the fenced
// metadata; the markdown body is never read into memory.
func readEntryFrontmatter(path string) (Frontmatter, error) {
	if _, err := entryFileInfo(path); err != nil {
		return Frontmatter{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Frontmatter{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxEntryFrontmatterBytes))
	if err != nil {
		return Frontmatter{}, err
	}
	fm, _, err := parseFrontmatter(raw)
	if err != nil {
		return Frontmatter{}, err
	}
	return fm, nil
}

func entryFileInfo(path string) (os.FileInfo, error) {
	// WalkDir does not follow directory symlinks, but it still presents file
	// symlinks as entries. Use Lstat so an operator-planted link cannot make a
	// tenant-scoped MCP search read an unrelated file outside the corpus root.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("knowledge: entry %q is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("knowledge: entry %q is not a regular file", path)
	}
	if info.Size() > maxEntryFileBytes {
		return nil, fmt.Errorf("knowledge: entry %q exceeds %d-byte limit", path, maxEntryFileBytes)
	}
	return info, nil
}

// Get returns the entry with id (no topic needed; the store walks).
// Returns ErrNotFound if no file matches.
func (s *Store) Get(ctx context.Context, id string) (Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(id)
}

func (s *Store) getLocked(id string) (Entry, error) {
	var found Entry
	var hit bool
	err := filepath.WalkDir(s.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		base := strings.TrimSuffix(filepath.Base(path), ".md")
		if base != id {
			return nil
		}
		raw, err := readEntryFile(path)
		if err != nil {
			return err
		}
		fm, body, err := parseFrontmatter(raw)
		if err != nil {
			return err
		}
		found = Entry{Frontmatter: fm, Body: string(body), Path: path}
		hit = true
		return fs.SkipAll
	})
	if err != nil {
		return Entry{}, err
	}
	if !hit {
		return Entry{}, ErrNotFound
	}
	return found, nil
}

// getLockedForTenant resolves an ID using a tenant boundary. IDs are normally
// generated and unique, but Add accepts operator-supplied IDs and permits the
// same ID in different topic directories. Prefer an exact tenant match over a
// shared entry; reject ambiguity instead of silently choosing a filesystem
// walk result. The store read lock must be held by the caller.
func (s *Store) getLockedForTenant(id, tenant string) (Entry, error) {
	var shared, owned []Entry
	err := filepath.WalkDir(s.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") || strings.TrimSuffix(filepath.Base(path), ".md") != id {
			return nil
		}
		raw, err := readEntryFile(path)
		if err != nil {
			return err
		}
		fm, body, err := parseFrontmatter(raw)
		if err != nil {
			return err
		}
		entry := Entry{Frontmatter: fm, Body: string(body), Path: path}
		if tenant == "" || fm.Tenant == tenant {
			owned = append(owned, entry)
		} else if fm.Tenant == "" {
			shared = append(shared, entry)
		}
		return nil
	})
	if err != nil {
		return Entry{}, err
	}
	candidates := owned
	if tenant != "" && len(candidates) == 0 {
		candidates = shared
	}
	if len(candidates) == 0 {
		return Entry{}, ErrNotFound
	}
	if len(candidates) > 1 {
		return Entry{}, fmt.Errorf("knowledge: entry id %q is ambiguous for tenant %q", id, tenant)
	}
	return candidates[0], nil
}

// List returns every entry, optionally filtered to one topic. Sorted by
// (topic asc, id asc) for deterministic output.
func (s *Store) List(ctx context.Context, topic string) ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Entry
	root := s.Root
	if topic != "" {
		root = filepath.Join(s.Root, topic)
		// Topic is exposed by the CLI and is also a reusable store API. Keep
		// read-side filtering inside the corpus root just like Add keeps
		// writes inside it; otherwise a value such as ../../tmp can make a
		// knowledge search walk arbitrary operator-readable directories.
		if !withinRoot(s.Root, root) {
			return nil, fmt.Errorf("knowledge: invalid topic %q (escapes the knowledge root)", topic)
		}
		if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		raw, err := readEntryFile(path)
		if err != nil {
			return err
		}
		fm, body, err := parseFrontmatter(raw)
		if err != nil {
			return fmt.Errorf("knowledge: parse %s: %w", path, err)
		}
		out = append(out, Entry{Frontmatter: fm, Body: string(body), Path: path})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Frontmatter.Topic != out[j].Frontmatter.Topic {
			return out[i].Frontmatter.Topic < out[j].Frontmatter.Topic
		}
		return out[i].Frontmatter.ID < out[j].Frontmatter.ID
	})
	return out, nil
}

// ListMetadata returns only parsed frontmatter for every entry, optionally
// filtered to one topic. It is intended for indexes and graph projections
// that need identity and ownership but never need the markdown body. The
// reader stops at the frontmatter fence and retains no entry body, so a
// rebuild cannot turn a large corpus into an aggregate body allocation.
func (s *Store) ListMetadata(ctx context.Context, topic string) ([]Frontmatter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	root := s.Root
	if topic != "" {
		root = filepath.Join(s.Root, topic)
		if !withinRoot(s.Root, root) {
			return nil, fmt.Errorf("knowledge: invalid topic %q (escapes the knowledge root)", topic)
		}
		if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
	}
	var out []Frontmatter
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		fm, err := readEntryFrontmatter(path)
		if err != nil {
			return fmt.Errorf("knowledge: parse %s: %w", path, err)
		}
		out = append(out, fm)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Topic != out[j].Topic {
			return out[i].Topic < out[j].Topic
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Search returns the top-N BM25 hits across the corpus.
func (s *Store) Search(ctx context.Context, query string, limit int) ([]Hit, error) {
	return s.searchForTenant(ctx, query, limit, "")
}

// SearchForTenant returns global entries plus entries owned by tenant. An
// empty tenant preserves the unscoped administrator view; callers serving a
// member or MCP tenant should always pass an explicit tenant.
func (s *Store) SearchForTenant(ctx context.Context, query string, limit int, tenant string) ([]Hit, error) {
	return s.searchForTenant(ctx, query, limit, tenant)
}

func (s *Store) searchForTenant(ctx context.Context, query string, limit int, tenant string) ([]Hit, error) {
	if limit <= 0 {
		limit = 10
	}
	qTokens := tokenize(query)
	if len(qTokens) == 0 {
		return nil, nil
	}

	// BM25 needs corpus-wide document frequencies and average length. Do that
	// accounting in a first pass, then score a second pass while retaining only
	// the requested top-N entries. The old ListForTenant path loaded every
	// body into one slice before ranking; a large or manually planted corpus
	// could therefore turn a bounded MCP search into an aggregate memory
	// allocation. Each pass still enforces the per-file read bound.
	s.mu.RLock()
	defer s.mu.RUnlock()
	df := map[string]int{}
	totalDocs := 0
	totalLen := 0
	walk := func(fn func(path string, fm Frontmatter, body []byte) error) error {
		return filepath.WalkDir(s.Root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() || !strings.HasSuffix(path, ".md") {
				return nil
			}
			raw, err := readEntryFile(path)
			if err != nil {
				return err
			}
			fm, body, err := parseFrontmatter(raw)
			if err != nil {
				return fmt.Errorf("knowledge: parse %s: %w", path, err)
			}
			if !visibleToTenant(Entry{Frontmatter: fm}, tenant) {
				return nil
			}
			return fn(path, fm, body)
		})
	}
	if err := walk(func(_ string, fm Frontmatter, body []byte) error {
		bodyTokens := tokenize(string(body))
		titleTokens := tokenize(fm.Title)
		totalDocs++
		totalLen += len(bodyTokens)
		seen := map[string]bool{}
		for _, token := range bodyTokens {
			if !seen[token] {
				df[token]++
				seen[token] = true
			}
		}
		for _, token := range titleTokens {
			if !seen[token] {
				df[token]++
				seen[token] = true
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if totalDocs == 0 {
		return nil, nil
	}
	avgLen := float64(totalLen) / float64(totalDocs)
	if avgLen == 0 {
		avgLen = 1
	}

	hits := make([]Hit, 0, limit)
	if err := walk(func(path string, fm Frontmatter, body []byte) error {
		entry := Entry{Frontmatter: fm, Body: string(body), Path: path}
		score := scoreEntryTokens(entry, tokenize(entry.Body), tokenize(fm.Title), qTokens, df, float64(totalDocs), avgLen, s.StaleDays)
		if score <= 0 {
			return nil
		}
		hits = append(hits, Hit{Entry: entry, Score: score})
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
		if len(hits) > limit {
			hits = hits[:limit]
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return hits, nil
}

// Supersede creates a new entry that points back at oldID via the
// supersedes frontmatter. The old entry stays on disk; git history is
// the audit. Returns the new entry.
func (s *Store) Supersede(ctx context.Context, oldID string, newEntry Entry, reason string) (Entry, error) {
	old, err := s.Get(ctx, oldID)
	if err != nil {
		return Entry{}, err
	}
	return s.supersedeFrom(ctx, old, newEntry, reason)
}

// SupersedeForTenant resolves the source entry using the same tenant boundary
// as MCP reads before creating its replacement. Without this method a caller
// could check GetForTenant and then have Supersede re-resolve a colliding ID
// from another topic or tenant.
func (s *Store) SupersedeForTenant(ctx context.Context, oldID, tenant string, newEntry Entry, reason string) (Entry, error) {
	s.mu.RLock()
	old, err := s.getLockedForTenant(oldID, tenant)
	s.mu.RUnlock()
	if err != nil {
		return Entry{}, err
	}
	return s.supersedeFrom(ctx, old, newEntry, reason)
}

func (s *Store) supersedeFrom(ctx context.Context, old Entry, newEntry Entry, reason string) (Entry, error) {
	if newEntry.Frontmatter.Topic == "" {
		newEntry.Frontmatter.Topic = old.Frontmatter.Topic
	}
	if newEntry.Frontmatter.Title == "" {
		newEntry.Frontmatter.Title = old.Frontmatter.Title
	}
	newEntry.Frontmatter.Supersedes = append(newEntry.Frontmatter.Supersedes, old.Frontmatter.ID)
	if reason != "" {
		newEntry.Frontmatter.Sources = append(newEntry.Frontmatter.Sources, "supersede-reason:"+reason)
	}
	return s.Add(ctx, newEntry)
}

// PromoteGold flips the gold flag on an existing entry. Used by the
// operator from the dashboard to weight an entry higher in prompts.
func (s *Store) PromoteGold(ctx context.Context, id string, gold bool) (Entry, error) {
	return s.mutate(ctx, id, "promote-gold:"+id, func(e *Entry) {
		e.Frontmatter.Gold = gold
	})
}

// MarkStale forces last_validated_at past the stale window so the
// entry is deprioritised in search until an operator re-validates.
func (s *Store) MarkStale(ctx context.Context, id string) (Entry, error) {
	return s.mutate(ctx, id, "mark-stale:"+id, func(e *Entry) {
		past := nowFn().AddDate(-1, 0, 0).UTC()
		e.Frontmatter.LastValidatedAt = past
	})
}

// IncrementCitation bumps the citation count. Called by the prompt
// assembler when an entry lands in a generated workflow's prompt. Does
// NOT commit (citation noise would balloon git history).
func (s *Store) IncrementCitation(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.getLocked(id)
	if err != nil {
		return err
	}
	e.Frontmatter.CitationCount++
	out := encodeFrontmatter(e.Frontmatter, e.Body)
	return os.WriteFile(e.Path, out, 0o600)
}

func (s *Store) mutate(ctx context.Context, id, msg string, fn func(*Entry)) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.getLocked(id)
	if err != nil {
		return Entry{}, err
	}
	fn(&e)
	out := encodeFrontmatter(e.Frontmatter, e.Body)
	if err := os.WriteFile(e.Path, out, 0o600); err != nil {
		return Entry{}, err
	}
	if err := s.commit(ctx, filepath.Dir(e.Path), msg); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func (s *Store) commit(ctx context.Context, dir, msg string) error {
	if s.Git == nil {
		return nil
	}
	return s.Git.Commit(ctx, dir, "knowledge", msg)
}

// newID returns "<topic-prefix>_<8 hex>" using the first letter of the
// topic. Predictable shape so operators reading git logs see at a glance
// which topic an id belongs to.
func newID(topic string) (string, error) {
	prefix := "k"
	for _, r := range topic {
		if r >= 'a' && r <= 'z' {
			prefix = string(r)
			break
		}
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("knowledge: id rand: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

// SetClockForTest swaps the package clock atomically. Restore by
// deferring the returned restore func. Test-only; no callers in
// production code.
func SetClockForTest(fn func() time.Time) (restore func()) {
	prev := nowFnPtr.Load()
	nowFnPtr.Store(&fn)
	return func() { nowFnPtr.Store(prev) }
}

// visibleToTenant reports whether an entry is readable by a viewer scoped to
// tenant. An empty scope is the admin/global view and sees everything; an
// entry with no tenant is shared material and is visible to everyone.
func visibleToTenant(e Entry, tenant string) bool {
	if tenant == "" {
		return true
	}
	return e.Frontmatter.Tenant == "" || e.Frontmatter.Tenant == tenant
}

// ListForTenant is List scoped to a viewer. Pass "" for the unscoped
// admin view. Use this for anything reachable by a member: the corpus mixes
// shared playbooks with per-tenant post-mortems, and List returns both.
func (s *Store) ListForTenant(ctx context.Context, topic, tenant string) ([]Entry, error) {
	all, err := s.List(ctx, topic)
	if err != nil {
		return nil, err
	}
	if tenant == "" {
		return all, nil
	}
	out := all[:0]
	for _, e := range all {
		if visibleToTenant(e, tenant) {
			out = append(out, e)
		}
	}
	return out, nil
}

// GetForTenant is Get scoped to a viewer. Returns ErrNotFound (never a
// permission error) when the entry belongs to another tenant, so guessing an
// id cannot confirm that it exists.
func (s *Store) GetForTenant(ctx context.Context, id, tenant string) (Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLockedForTenant(id, tenant)
}
