package esign

import (
	"strings"
	"testing"
	"time"
)

func TestLifecycleEventValidate(t *testing.T) {
	t.Parallel()
	valid := LifecycleEvent{
		EventID:             "event-1",
		Kind:                "document.completed",
		OccurredAt:          time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC),
		AutomationRequestID: "request-1",
		DocumentID:          "document-1",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid lifecycle event: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*LifecycleEvent)
	}{
		{name: "event ID", mutate: func(event *LifecycleEvent) { event.EventID = "" }},
		{name: "kind", mutate: func(event *LifecycleEvent) { event.Kind = " document.completed" }},
		{name: "occurred at", mutate: func(event *LifecycleEvent) { event.OccurredAt = time.Time{} }},
		{name: "automation request ID", mutate: func(event *LifecycleEvent) { event.AutomationRequestID = "bad\nvalue" }},
		{name: "document ID", mutate: func(event *LifecycleEvent) { event.DocumentID = strings.Repeat("x", maxIdentifierSize+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := valid
			test.mutate(&event)
			if err := event.Validate(); err == nil {
				t.Fatal("invalid lifecycle event accepted")
			}
		})
	}
}
