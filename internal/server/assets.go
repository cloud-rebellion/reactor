package server

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strings"
)

//go:embed assets/*
var assetsFS embed.FS

// assetMounts wires every embedded static asset onto a /assets/<name>
// route. Currently ships cytoscape.min.js for the dashboard's DAG
// render. Kept tiny: anything heavier than a JS lib should land as a
// reverse-proxied CDN, not embedded into the binary.
func (s *Server) assets(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	if name == "" || strings.Contains(name, "..") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	body, err := assetsFS.ReadFile("assets/" + name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(name, ".woff2"):
		w.Header().Set("Content-Type", "font/woff2")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css")
	}
	// Asset URLs are stable across binary rebuilds, so immutable caching would
	// pin a browser to stale editor/security JavaScript forever. Keep caching
	// efficient with a content ETag while requiring a cheap revalidation when
	// the binary changes.
	digest := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(digest[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	if assetETagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

func assetETagMatches(header, current string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == current || strings.TrimPrefix(candidate, "W/") == current {
			return true
		}
	}
	return false
}
