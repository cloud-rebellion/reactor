package server

import (
	"context"
	"encoding/json"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

const (
	// The node drawer is a browser read surface. Keep historical output out of
	// an unbounded ListSteps call: one imported run can contain arbitrarily
	// large blobs and the editor only needs a bounded sample for lineage.
	maxNodeDataflowStepRows    = 256
	maxNodeDataflowOutputBytes = 64 << 10
	maxNodeDataflowErrorBytes  = 8 << 10
)

// node_dataflow.go surfaces declared predecessors and successors for one node
// in the visual editor, plus a bounded output sample from the most recent run.
// A dependency is an ordering assertion, not proof that Go code passed that
// predecessor's output into this node.

// nodeConn is one connected step, optionally carrying the upstream step's last
// recorded output so the drawer can show real data.
type nodeConn struct {
	Name            string          `json:"name"`
	Kind            string          `json:"kind,omitempty"`
	Output          json.RawMessage `json:"output,omitempty"`
	OutputBytes     int             `json:"output_bytes,omitempty"`
	OutputTruncated bool            `json:"output_truncated,omitempty"`
	Status          string          `json:"status,omitempty"`
}

// dagShape is the subset of dag.json we need to walk connections.
type dagShape struct {
	Steps []struct {
		Name      string   `json:"name"`
		Kind      string   `json:"kind"`
		DependsOn []string `json:"depends_on"`
	} `json:"steps"`
	Nodes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	} `json:"nodes"`
	Edges []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"edges"`
}

// dagConnections returns declared predecessors and successors of step.
// steps[].depends_on is authoritative for executable steps; top-level edges[]
// belongs only to the nodes[] encoding, as in the canvas and run flow.
func dagConnections(dagBytes []byte, step string) (upstream, downstream []nodeConn) {
	var d dagShape
	if err := json.Unmarshal(dagBytes, &d); err != nil {
		return nil, nil
	}
	kindOf := map[string]string{}
	// Keep the node editor in lockstep with the dashboard/MCP flow
	// normalizers: the first executable declaration wins. Legacy rows can
	// contain duplicate step names (or a stale visual companion); letting a
	// later duplicate overwrite the kind or contribute dependencies would make
	// this drawer describe a different graph than the canvas and execution
	// proof. Retain the first declarations for both the kind table and the
	// relationship walk below.
	executableSteps := make([]struct {
		Name      string
		Kind      string
		DependsOn []string
	}, 0, len(d.Steps))
	// A non-empty steps[] is the executable representation. A stale nodes[]
	// companion must not add IDs or kinds to the drawer: the canvas, MCP flow
	// projection, and accessible summary all use this precedence so the data
	// lineage cannot describe work the executable graph does not contain.
	usesExecutableSteps := len(d.Steps) > 0
	if usesExecutableSteps {
		for _, s := range d.Steps {
			if s.Name == "" {
				continue
			}
			if _, exists := kindOf[s.Name]; exists {
				continue
			}
			kindOf[s.Name] = s.Kind
			executableSteps = append(executableSteps, struct {
				Name      string
				Kind      string
				DependsOn []string
			}{Name: s.Name, Kind: s.Kind, DependsOn: s.DependsOn})
		}
	} else {
		// The visual-editor encoding uses nodes[].id (with name as a legacy
		// fallback) instead of steps[].name. Keep the drawer's lineage view in
		// lockstep with the Cytoscape/MCP normalizers so clicking a visual node
		// does not falsely present it as an unconnected starting node.
		for _, n := range d.Nodes {
			name := n.ID
			if name == "" {
				name = n.Name
			}
			if name != "" {
				if _, exists := kindOf[name]; exists {
					continue
				}
				kindOf[name] = n.Kind
			}
		}
	}
	upSeen, downSeen := map[string]bool{}, map[string]bool{}
	addUp := func(name string) {
		if name == "" || name == step || upSeen[name] {
			return
		}
		if _, ok := kindOf[name]; !ok {
			return
		}
		upSeen[name] = true
		upstream = append(upstream, nodeConn{Name: name, Kind: kindOf[name]})
	}
	addDown := func(name string) {
		if name == "" || name == step || downSeen[name] {
			return
		}
		if _, ok := kindOf[name]; !ok {
			return
		}
		downSeen[name] = true
		downstream = append(downstream, nodeConn{Name: name, Kind: kindOf[name]})
	}
	for _, s := range executableSteps {
		if s.Name == step {
			for _, dep := range s.DependsOn {
				addUp(dep)
			}
		}
		for _, dep := range s.DependsOn {
			if dep == step {
				addDown(s.Name)
			}
		}
	}
	if !usesExecutableSteps {
		for _, e := range d.Edges {
			// Ignore stale or malformed edge endpoints. Besides keeping the drawer
			// bounded, this mirrors the visual renderer and prevents an edge to a
			// visual-only node from inventing data available to an executable step.
			if _, ok := kindOf[e.From]; !ok {
				continue
			}
			if _, ok := kindOf[e.To]; !ok {
				continue
			}
			if e.To == step {
				addUp(e.From)
			}
			if e.From == step {
				addDown(e.To)
			}
		}
	}
	return upstream, downstream
}

// latestStepOutputs returns samples only when the most recent run was pinned
// to the exact version/artifact represented by the drawer DAG. An older or
// unpinned run cannot supply sample values for a revised graph.
func (s *Server) latestStepOutputs(ctx context.Context, slug, tenantID string, drawerDAG []byte) (map[string]nodeConn, string) {
	out := map[string]nodeConn{}
	if s.Journal == nil || len(drawerDAG) == 0 || len(drawerDAG) > maxFlowDAGBytes {
		return out, ""
	}
	wfID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, tenantID)
	if err != nil {
		return out, ""
	}
	version, err := s.Journal.CurrentWorkflowVersionRecordBounded(ctx, wfID, maxFlowDAGBytes)
	if err != nil || version.DAGTruncated || version.Version < 1 || version.ArtifactSHA256 == "" ||
		registry.VerifyDAGSnapshot(drawerDAG, version.DAG) != nil {
		return out, ""
	}
	runs, err := s.Journal.ListRuns(ctx, journal.RunFilter{WorkflowID: wfID, Limit: 1})
	if err != nil || len(runs) == 0 {
		return out, ""
	}
	runID := runs[0].ID
	run, err := s.Journal.GetRunForTenantMetadata(ctx, runID, tenantID, 0)
	if err != nil || run.WorkflowID != wfID || run.WorkflowVersion != version.Version ||
		run.WorkflowArtifactSHA256 != version.ArtifactSHA256 {
		return out, ""
	}
	steps, err := s.Journal.ListLatestStepsPageForTenantBounded(ctx, runID, tenantID, maxNodeDataflowStepRows, 0, maxNodeDataflowOutputBytes, maxNodeDataflowErrorBytes)
	if err != nil {
		return out, ""
	}
	// The bounded journal projection remains chronological; the last row for a
	// step name wins so we show the final attempt's output. Large output is
	// represented by an explicit receipt instead of being silently presented as
	// an empty sample.
	for _, st := range steps {
		out[st.StepName] = nodeConn{
			Name: st.StepName, Output: st.OutputJSONB, OutputBytes: st.OutputBytes,
			OutputTruncated: st.OutputTruncated, Status: st.Status,
		}
	}
	return out, runID
}

// nodeDataflow assembles the connections for step, enriching each upstream
// entry with sample output from the latest run when available.
func (s *Server) nodeDataflow(ctx context.Context, slug, dir, step, tenantID string) (upstream, downstream []nodeConn, runID string) {
	dagBytes, _, _ := readFirstAvailableBounded(dir, maxFlowDAGBytes, "dag.json", "source/dag.json")
	upstream, downstream = dagConnections(dagBytes, step)
	outputs, runID := s.latestStepOutputs(ctx, slug, tenantID, dagBytes)
	for i := range upstream {
		if o, ok := outputs[upstream[i].Name]; ok {
			upstream[i].Output = o.Output
			upstream[i].OutputBytes = o.OutputBytes
			upstream[i].OutputTruncated = o.OutputTruncated
			upstream[i].Status = o.Status
		}
	}
	return upstream, downstream, runID
}
