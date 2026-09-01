package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/bright-interaction/reactor/internal/codegen"
)

//go:embed scaffolds/*/*
var scaffoldFS embed.FS

// availableTemplates is the list shown in usage + accepted by --template.
// Order matches the README progression: simplest first.
var availableTemplates = []string{
	"cron-echo",
	"webhook-step-secret",
	"scheduled-rotation",
	"approval-flow",
	"stripe-webhook",
	"hash-esign-bridge",
	"hash-esign-lifecycle",
	"github-pr-reviewer",
	"scheduled-report",
}

// cmdNew renders an embedded scaffold into a destination directory.
//
//	reactor new <template> <slug> [--dest <dir>]
//
// Each template is a directory under cmd/reactor/scaffolds/ containing
// .tmpl files. Files are rendered with text/template so the slug + date
// substitute into the generated source. Output: a self-contained workflow
// directory ready for `reactor workflow build`.
func cmdNew(_ context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("new", flag.ContinueOnError)
	dest := fs.String("dest", ".", "destination directory; new <slug>/ subdir is created here")
	orderedArgs, err := reorderNewArgs(args)
	if err != nil {
		return err
	}
	if err := fs.Parse(orderedArgs); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("new: usage: reactor new <template> <slug> [--dest <dir>]\n\navailable templates:\n  %s",
			strings.Join(availableTemplates, "\n  "))
	}
	tmplName := fs.Arg(0)
	slug := fs.Arg(1)

	if !knownTemplate(tmplName) {
		return fmt.Errorf("new: unknown template %q (have: %s)",
			tmplName, strings.Join(availableTemplates, ", "))
	}
	if !codegen.IsValidSlug(slug) {
		return fmt.Errorf("new: slug %q must match ^[a-z][a-z0-9-]*$", slug)
	}

	target := filepath.Join(*dest, slug)
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("new: %s already exists; refusing to overwrite", target)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("new: mkdir %s: %w", target, err)
	}

	data := struct {
		Slug, Date string
	}{
		Slug: slug,
		Date: time.Now().UTC().Format("2006-01-02"),
	}

	if err := renderScaffold(tmplName, target, data); err != nil {
		return err
	}

	fmt.Printf("created %s/ from template %s\n\nNext steps:\n  cd %s\n  reactor workflow build --src . --slug %s\n  %s\n",
		target, tmplName, target, slug, workflowRegisterHint(slug))
	return nil
}

func workflowRegisterHint(slug string) string {
	return fmt.Sprintf("reactor workflow register --db <url> --slug %s --src main.go --dag dag.json --artifact-sha256 <sha256-printed-by-build>", slug)
}

// reorderNewArgs supports the documented positional-first form
// `reactor new <template> <slug> --dest <dir>`. The shared reorderArgs helper
// can only move --name=value and boolean flags because it cannot know which
// arbitrary flags consume a following value.
func reorderNewArgs(args []string) ([]string, error) {
	normalized := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		if args[index] == "--dest" || args[index] == "-dest" {
			if index+1 >= len(args) {
				return nil, errors.New("new: --dest requires a directory")
			}
			normalized = append(normalized, args[index]+"="+args[index+1])
			index++
			continue
		}
		normalized = append(normalized, args[index])
	}
	return reorderArgs(normalized), nil
}

func knownTemplate(name string) bool {
	for _, t := range availableTemplates {
		if t == name {
			return true
		}
	}
	return false
}

func renderScaffold(name, dest string, data any) error {
	root := "scaffolds/" + name
	return walkScaffold(root, func(path string, body []byte) error {
		// Strip the "scaffolds/<name>/" prefix + the ".tmpl" suffix.
		rel := strings.TrimPrefix(path, root+"/")
		rel = strings.TrimSuffix(rel, ".tmpl")
		out := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		t, err := template.New(rel).Parse(string(body))
		if err != nil {
			return fmt.Errorf("new: parse %s: %w", path, err)
		}
		f, err := os.Create(out)
		if err != nil {
			return fmt.Errorf("new: create %s: %w", out, err)
		}
		defer f.Close()
		if err := t.Execute(f, data); err != nil {
			return fmt.Errorf("new: execute %s: %w", path, err)
		}
		return nil
	})
}

func walkScaffold(root string, fn func(path string, body []byte) error) error {
	entries, err := fs.ReadDir(scaffoldFS, root)
	if err != nil {
		return errors.New("new: scaffold not found: " + root)
	}
	for _, e := range entries {
		full := root + "/" + e.Name()
		if e.IsDir() {
			if err := walkScaffold(full, fn); err != nil {
				return err
			}
			continue
		}
		body, err := scaffoldFS.ReadFile(full)
		if err != nil {
			return err
		}
		if err := fn(full, body); err != nil {
			return err
		}
	}
	return nil
}
