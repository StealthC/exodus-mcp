package mcp

import "sync"

// toolMetrics is one per-tool accumulator.
type toolMetrics struct {
	calls  uint64
	errors uint64
}

// metricsStore accumulates per-tool call/error counts and per-artifact-kind
// counts for the /metrics endpoint. It is safe for concurrent use.
type metricsStore struct {
	mu        sync.Mutex
	tools     map[string]*toolMetrics
	artifacts map[string]uint64
}

func newMetricsStore() *metricsStore {
	return &metricsStore{
		tools:     make(map[string]*toolMetrics),
		artifacts: make(map[string]uint64),
	}
}

// recordCall credits one tool invocation, optionally a failed one.
func (m *metricsStore) recordCall(tool string, failed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.tools[tool]
	if entry == nil {
		entry = &toolMetrics{}
		m.tools[tool] = entry
	}
	entry.calls++
	if failed {
		entry.errors++
	}
}

// recordArtifact credits one stored artifact of the given kind. The hook
// fires from the artifact store, which knows the artifact kind but not the
// producing tool, so counts are keyed per kind.
func (m *metricsStore) recordArtifact(kind string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.artifacts[kind]++
}

// snapshot returns a copy of the accumulated counters shaped for JSON.
func (m *metricsStore) snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()

	tools := make(map[string]any, len(m.tools))
	var totalCalls, totalErrors, totalArtifacts uint64
	for name, entry := range m.tools {
		tools[name] = map[string]any{
			"calls":      entry.calls,
			"errors":     entry.errors,
			"error_rate": errorRate(entry.errors, entry.calls),
		}
		totalCalls += entry.calls
		totalErrors += entry.errors
	}
	artifacts := make(map[string]uint64, len(m.artifacts))
	for kind, count := range m.artifacts {
		artifacts[kind] = count
		totalArtifacts += count
	}
	return map[string]any{
		"tools": tools,
		"artifacts": map[string]any{
			"by_kind": artifacts,
			"total":   totalArtifacts,
		},
		"totals": map[string]uint64{
			"calls":  totalCalls,
			"errors": totalErrors,
		},
	}
}

// errorRate is failures per invocation, 0 when nothing was called.
func errorRate(errors, calls uint64) float64 {
	if calls == 0 {
		return 0
	}
	return float64(errors) / float64(calls)
}
