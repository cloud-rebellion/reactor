package registry

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidateDAGAcceptsCanonicalShape(t *testing.T) {
	t.Parallel()
	good := []byte(`{
		"slug": "send-welcome",
		"version": "0.1.0",
		"steps": [
			{"name":"fetch", "kind":"step", "timeout_seconds": 5},
			{"name":"sleep", "kind":"sleep", "depends_on":["fetch"]},
			{"name":"notify","kind":"step", "depends_on":["sleep"], "idempotency_key":"x:welcome"}
		]
	}`)
	if err := ValidateDAG(good); err != nil {
		t.Fatalf("expected canonical shape to validate: %v", err)
	}
}

func TestValidateDAGRejectsBadSlug(t *testing.T) {
	t.Parallel()
	bad := []byte(`{"slug": "../escape", "version": "0.1.0", "steps": []}`)
	err := ValidateDAG(bad)
	var dse *DAGSchemaError
	if !errors.As(err, &dse) {
		t.Fatalf("expected DAGSchemaError, got %v", err)
	}
	found := false
	for _, is := range dse.Issues {
		if is.Path == "/slug" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected slug issue, got %v", dse.Issues)
	}
}

func TestValidateDAGRejectsBadKind(t *testing.T) {
	t.Parallel()
	bad := []byte(`{"slug": "ok", "version": "0.1.0", "steps": [{"name":"a","kind":"explode"}]}`)
	err := ValidateDAG(bad)
	var dse *DAGSchemaError
	if !errors.As(err, &dse) {
		t.Fatalf("expected DAGSchemaError, got %v", err)
	}
}

func TestValidateDAGRejectsDuplicateStepName(t *testing.T) {
	t.Parallel()
	bad := []byte(`{"slug":"ok","version":"0.1.0","steps":[{"name":"a","kind":"step"},{"name":"a","kind":"step"}]}`)
	err := ValidateDAG(bad)
	var dse *DAGSchemaError
	if !errors.As(err, &dse) {
		t.Fatalf("expected DAGSchemaError, got %v", err)
	}
	if !strings.Contains(err.Error(), "duplicate step name") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestValidateDAGRejectsDuplicateObjectKeys(t *testing.T) {
	t.Parallel()
	// encoding/json would silently retain the second kind value here. The
	// canonical DAG gate must reject the ambiguity before any source/DAG or
	// review projection can observe a different graph than the author sent.
	for _, raw := range []string{
		`{"steps":[{"name":"send","kind":"step","kind":"sleep"}]}`,
		`{"steps":[{"name":"send","kind":"step"}],"steps":[{"name":"other","kind":"step"}]}`,
	} {
		if err := ValidateDAG([]byte(raw)); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
			t.Fatalf("duplicate DAG key accepted: %v", err)
		}
	}
}

func TestValidateDAGRejectsParseError(t *testing.T) {
	t.Parallel()
	if err := ValidateDAG([]byte("not json")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestValidateDAGRejectsEmpty(t *testing.T) {
	t.Parallel()
	if err := ValidateDAG(nil); err == nil {
		t.Fatal("expected empty-body error")
	}
}

func TestValidateDAGRejectsDanglingDependency(t *testing.T) {
	t.Parallel()
	err := ValidateDAG([]byte(`{"slug":"ok","version":"0.1.0","steps":[{"name":"send","kind":"step","depends_on":["missing"]}]}`))
	if err == nil || !strings.Contains(err.Error(), "unknown step") {
		t.Fatalf("expected dangling dependency rejection, got %v", err)
	}
}

func TestValidateDAGRejectsCycles(t *testing.T) {
	t.Parallel()
	err := ValidateDAG([]byte(`{"slug":"ok","version":"0.1.0","steps":[{"name":"a","kind":"step","depends_on":["b"]},{"name":"b","kind":"step","depends_on":["a"]}]}`))
	if err == nil || !strings.Contains(err.Error(), "dependency cycle") {
		t.Fatalf("expected cycle rejection, got %v", err)
	}
}

func TestValidateDAGRejectsVisualGraphCycle(t *testing.T) {
	t.Parallel()
	err := ValidateDAG([]byte(`{"nodes":[{"id":"a","kind":"step"},{"id":"b","kind":"step"}],"edges":[{"from":"a","to":"b"},{"from":"b","to":"a"}]}`))
	if err == nil || !strings.Contains(err.Error(), "dependency cycle") {
		t.Fatalf("expected visual cycle rejection, got %v", err)
	}
}

func TestValidateDAGRejectsVisualNodeKind(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		dag  string
		want string
	}{
		{name: "missing", dag: `{"nodes":[{"id":"a"}]}`, want: "/nodes/0/kind"},
		{name: "wrong type", dag: `{"nodes":[{"id":"a","kind":7}]}`, want: "/nodes/0/kind"},
		{name: "unknown", dag: `{"nodes":[{"id":"a","kind":"explode"}]}`, want: `got "explode"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDAG([]byte(tc.dag))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected visual node kind rejection containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateDAGRejectsFieldsThatBreakVisualProjection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, dag, path string }{
		{"step uses scalar", `{"steps":[{"name":"send","kind":"step","uses":"credential"}]}`, "/steps/0/uses"},
		{"step uses non-string", `{"steps":[{"name":"send","kind":"step","uses":[7]}]}`, "/steps/0/uses/0"},
		{"node uses scalar", `{"nodes":[{"id":"send","kind":"step","uses":"credential"}]}`, "/nodes/0/uses"},
		{"node label non-string", `{"nodes":[{"id":"send","kind":"step","label":7}]}`, "/nodes/0/label"},
		{"node id non-string", `{"nodes":[{"id":7,"name":"send","kind":"step"}]}`, "/nodes/0/id"},
		{"node name non-string", `{"nodes":[{"id":"send","name":7,"kind":"step"}]}`, "/nodes/0/name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDAG([]byte(tc.dag))
			if err == nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("malformed visual field should fail at %s, got %v", tc.path, err)
			}
		})
	}
}

func TestValidateDAGRejectsTooManySteps(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"slug":"ok","version":"0.1.0","steps":[`)
	for i := 0; i < maxDAGSteps+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"name":"s`)
		b.WriteString(fmt.Sprint(i))
		b.WriteString(`","kind":"step"}`)
	}
	b.WriteString(`]}`)
	if err := ValidateDAG([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("expected step cap rejection, got %v", err)
	}
}

func TestValidateDAGRejectsTooManyEdges(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"nodes":[{"id":"root","kind":"step"},{"id":"sink","kind":"step"}],"edges":[`)
	for i := 0; i < maxDAGEdges+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// Repeated valid endpoints are intentional: the edge budget must fail
		// closed before a caller can force unbounded dependency/cycle work.
		fmt.Fprint(&b, `{"from":"root","to":"sink"}`)
	}
	b.WriteString(`]}`)
	if err := ValidateDAG([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("expected edge cap rejection, got %v", err)
	}
}

func TestValidateDAGRejectsOversizedBodyBeforeParsing(t *testing.T) {
	t.Parallel()
	src := []byte(`{"steps":[]}` + strings.Repeat(" ", maxDAGBytes))
	if err := ValidateDAG(src); err == nil || !strings.Contains(err.Error(), "body exceeds") {
		t.Fatalf("expected body-size rejection, got %v", err)
	}
}

func TestValidateDAGRejectsMixedNonEmptyEncodings(t *testing.T) {
	t.Parallel()
	err := ValidateDAG([]byte(`{"steps":[{"name":"send","kind":"step"}],"nodes":[{"id":"send","kind":"side_effect"}]}`))
	if err == nil || !strings.Contains(err.Error(), "either steps or nodes") {
		t.Fatalf("expected mixed-encoding rejection, got %v", err)
	}
}

func TestValidateDAGRejectsEdgesIgnoredByStepsProjection(t *testing.T) {
	t.Parallel()
	for _, dag := range []string{
		`{"steps":[{"name":"fetch","kind":"step"},{"name":"send","kind":"step"}],"edges":[{"from":"fetch","to":"send"}]}`,
		`{"steps":[{"name":"fetch","kind":"step"},{"name":"send","kind":"step","depends_on":["fetch"]}],"edges":[{"from":"fetch","to":"send"}]}`,
		`{"steps":[{"name":"fetch","kind":"step"}],"edges":{"from":"fetch"}}`,
	} {
		if err := ValidateDAG([]byte(dag)); err == nil || !strings.Contains(err.Error(), "/edges") || !strings.Contains(err.Error(), "depends_on") {
			t.Fatalf("ignored top-level edges accepted or lacked correction: %v", err)
		}
	}
	if err := ValidateDAG([]byte(`{"steps":[{"name":"fetch","kind":"step"}],"edges":[]}`)); err != nil {
		t.Fatalf("empty legacy edge list rejected: %v", err)
	}
}

func TestValidateDAGRejectsEdgesWithoutPopulatedNodes(t *testing.T) {
	t.Parallel()
	for _, dag := range []string{
		`{"steps":[],"edges":[{"from":"fetch","to":"send"}]}`,
		`{"steps":[],"nodes":[],"edges":[{"from":"fetch","to":"send"}]}`,
		`{"steps":[],"edges":{"from":"fetch","to":"send"}}`,
	} {
		if err := ValidateDAG([]byte(dag)); err == nil || !strings.Contains(err.Error(), "/edges") || !strings.Contains(err.Error(), "populated nodes") {
			t.Fatalf("unowned top-level edges accepted or lacked correction: %v", err)
		}
	}
	if err := ValidateDAG([]byte(`{"steps":[],"nodes":[{"id":"fetch","kind":"step"},{"id":"send","kind":"step"}],"edges":[{"from":"fetch","to":"send"}]}`)); err != nil {
		t.Fatalf("legacy empty steps with a populated nodes graph rejected: %v", err)
	}
}

func TestValidateDAGRejectsDependenciesIgnoredByNodesProjection(t *testing.T) {
	t.Parallel()
	for _, dag := range []string{
		`{"nodes":[{"id":"fetch","kind":"step"},{"id":"send","kind":"step","depends_on":["fetch"]}]}`,
		`{"nodes":[{"id":"fetch","kind":"step"},{"id":"send","kind":"step","depends_on":["fetch"]}],"edges":[{"from":"fetch","to":"send"}]}`,
		`{"nodes":[{"id":"send","kind":"step","depends_on":"fetch"}]}`,
	} {
		if err := ValidateDAG([]byte(dag)); err == nil || !strings.Contains(err.Error(), "/depends_on") || !strings.Contains(err.Error(), "edges") {
			t.Fatalf("ignored node dependencies accepted or lacked correction: %v", err)
		}
	}
	if err := ValidateDAG([]byte(`{"nodes":[{"id":"fetch","kind":"step","depends_on":[]}]}`)); err != nil {
		t.Fatalf("empty legacy dependency list rejected: %v", err)
	}
}

func TestValidateDAGAllowsEmptyLegacyStepsWithVisualNodes(t *testing.T) {
	t.Parallel()
	if err := ValidateDAG([]byte(`{"steps":[],"nodes":[{"id":"send","kind":"step"}]}`)); err != nil {
		t.Fatalf("expected empty legacy steps to coexist with visual nodes: %v", err)
	}
}

func TestValidateDAGAcceptsDeclaredBlockFlowInDurableStep(t *testing.T) {
	t.Parallel()
	for _, dag := range []string{
		`{"steps":[{"name":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"},{"id":"mapItems","kind":"iterate"},{"id":"total","kind":"aggregate"},{"id":"join","kind":"merge"}],"edges":[{"from":"route","to":"mapItems","route":"yes"},{"from":"mapItems","to":"total"},{"from":"total","to":"join"}]}}]}`,
		`{"steps":[],"nodes":[{"id":"process","kind":"step","visual_flow":{"blocks":[{"id":"route","kind":"split"}]}}]}`,
	} {
		if err := ValidateDAG([]byte(dag)); err != nil {
			t.Fatalf("declared block flow rejected: %v", err)
		}
	}
}

func TestValidateDAGRejectsMisleadingOrInvalidBlockFlow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, dag, want string }{
		{"non durable step", `{"steps":[{"name":"wait","kind":"sleep","visual_flow":{"blocks":[{"id":"each","kind":"iterate"}]}}]}`, "/steps/0/visual_flow"},
		{"unknown kind", `{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"do","kind":"credential"}]}}]}`, "/steps/0/visual_flow/blocks/0/kind"},
		{"dangling", `{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"do","kind":"map"}],"edges":[{"from":"do","to":"missing"}]}}]}`, "/steps/0/visual_flow/edges/0"},
		{"cycle", `{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"a","kind":"map"},{"id":"b","kind":"filter"}],"edges":[{"from":"a","to":"b"},{"from":"b","to":"a"}]}}]}`, "must be acyclic"},
		{"control label", `{"steps":[{"name":"work","kind":"step","visual_flow":{"blocks":[{"id":"do","kind":"map","label":"bad\nlabel"}]}}]}`, "/steps/0/visual_flow/blocks/0/label"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDAG([]byte(tc.dag))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid visual flow accepted or wrong issue, want %q: %v", tc.want, err)
			}
		})
	}
}
