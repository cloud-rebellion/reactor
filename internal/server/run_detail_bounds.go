package server

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// boundRunDetailLogs keeps the server-rendered run page bounded even when a
// live in-memory tail contains a line larger than the journal read limit. Log
// text is untrusted data; an omitted line is represented by a size receipt so
// the page never silently looks complete.
func boundRunDetailLogs(lines []string) []string {
	out := make([]string, 0, minInt(len(lines), maxRunDetailLogLines)+1)
	used := 0
	omitted := false
	for i, line := range lines {
		if i >= maxRunDetailLogLines {
			omitted = true
			break
		}
		bytes := len([]byte(line))
		if bytes > maxRunDetailLogLineBytes {
			line = runDetailLogOmitted(bytes)
		} else {
			line = strings.ToValidUTF8(line, "�")
		}
		if used+len([]byte(line)) > maxRunDetailLogBytes {
			omitted = true
			break
		}
		out = append(out, line)
		used += len([]byte(line))
	}
	if omitted {
		out = append(out, "[reactor: additional log lines omitted]")
	}
	return out
}

func boundRunDetailPersistedLogs(rows []journal.BoundedRunLogLine) []string {
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Truncated {
			lines = append(lines, runDetailLogOmitted(row.Bytes))
		} else {
			lines = append(lines, row.Text)
		}
	}
	return boundRunDetailLogs(lines)
}

func boundRunDetailLogLine(line string) string {
	bounded := boundRunDetailLogs([]string{line})
	if len(bounded) == 0 {
		return ""
	}
	return bounded[0]
}

func runDetailLogOmitted(bytes int) string {
	if bytes <= 0 {
		return "[reactor: log line omitted]"
	}
	marker := fmt.Sprintf("[reactor: log line omitted (%d durable bytes)]", bytes)
	if len([]byte(marker)) <= maxRunDetailLogLineBytes {
		return marker
	}
	// The fixed marker is comfortably below the limit today, but retain the
	// invariant if the byte budget is tightened later and avoid cutting UTF-8.
	marker = marker[:maxRunDetailLogLineBytes]
	for len(marker) > 0 && !utf8.ValidString(marker) {
		marker = marker[:len(marker)-1]
	}
	return marker
}
