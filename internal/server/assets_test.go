package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssetsUseRevalidatingContentETags(t *testing.T) {
	t.Parallel()

	server := &Server{}
	firstReq := httptest.NewRequest(http.MethodGet, "/assets/workflow-editor.js", nil)
	first := httptest.NewRecorder()
	server.assets(first, firstReq)
	if first.Code != http.StatusOK || first.Body.Len() == 0 {
		t.Fatalf("first asset response = status %d, bytes %d; want 200 with body", first.Code, first.Body.Len())
	}
	etag := first.Header().Get("ETag")
	if etag == "" || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Fatalf("asset ETag = %q; want quoted digest", etag)
	}
	if got := first.Header().Get("Cache-Control"); got != "public, max-age=0, must-revalidate" {
		t.Fatalf("asset Cache-Control = %q; want revalidation", got)
	}

	for _, candidate := range []string{etag, "W/" + etag, "\"different\", " + etag} {
		req := httptest.NewRequest(http.MethodGet, "/assets/workflow-editor.js", nil)
		req.Header.Set("If-None-Match", candidate)
		rec := httptest.NewRecorder()
		server.assets(rec, req)
		if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
			t.Fatalf("If-None-Match %q = status %d, bytes %d; want empty 304", candidate, rec.Code, rec.Body.Len())
		}
	}
}

func TestAssetETagMatchesHandlesListsAndWeakTags(t *testing.T) {
	t.Parallel()
	for header, want := range map[string]bool{
		`"abc"`:              true,
		`W/"abc"`:            true,
		`"other", W/"abc"`:   true,
		`*`:                  true,
		`"other"`:            false,
		`W/"other", "later"`: false,
	} {
		if got := assetETagMatches(header, `"abc"`); got != want {
			t.Errorf("assetETagMatches(%q) = %v, want %v", header, got, want)
		}
	}
}
