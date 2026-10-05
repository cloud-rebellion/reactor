package server

import (
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestRenderTilesSuccessRateUsesCompletedRuns(t *testing.T) {
	markup := renderTiles(journal.Analytics{
		TotalRuns: 100,
		RunsByStatus: map[string]int{
			journal.StatusSucceeded: 8,
			journal.StatusFailed:    2,
			journal.StatusRunning:   20,
			"queued":                70,
		},
	})
	if !strings.Contains(markup, "80.0% of completed runs") {
		t.Fatalf("success rate fell with unfinished work: %s", markup)
	}
}
