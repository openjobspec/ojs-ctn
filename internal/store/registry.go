package store

import (
	"encoding/json"
	"sort"
)

// ListOptions controls pagination for List queries.
type ListOptions struct {
	Offset int
	Limit  int
}

// ListResult is a paginated list of entries.
type ListResult struct {
	Entries []Entry `json:"entries"`
	Total   int     `json:"total"`
	Offset  int     `json:"offset"`
	Limit   int     `json:"limit"`
}

// List returns a paginated slice of entries, newest first.
func (s *Store) List(opts ListOptions) ListResult {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 1000 {
		opts.Limit = 1000
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.entries)
	if opts.Offset >= total {
		return ListResult{Entries: []Entry{}, Total: total, Offset: opts.Offset, Limit: opts.Limit}
	}

	// Reverse order (newest first) without modifying s.entries.
	end := total - opts.Offset
	start := end - opts.Limit
	if start < 0 {
		start = 0
	}
	slice := make([]Entry, end-start)
	for i, j := end-1, 0; i >= start; i-- {
		e := s.entries[i]
		if len(e.WitnessCosignatures) > 0 {
			cs := make([]WitnessCosignature, len(e.WitnessCosignatures))
			copy(cs, e.WitnessCosignatures)
			e.WitnessCosignatures = cs
		}
		slice[j] = e
		j++
	}

	return ListResult{Entries: slice, Total: total, Offset: opts.Offset, Limit: opts.Limit}
}

// BackendSummary aggregates attestation info for a single backend.
type BackendSummary struct {
	BackendName     string `json:"backend_name"`
	LatestEntryID   string `json:"latest_entry_id"`
	LatestLevel     int    `json:"latest_level"`
	LatestConformant bool  `json:"latest_conformant"`
	LatestRunAt     string `json:"latest_run_at"`
	TotalRuns       int    `json:"total_runs"`
	WitnessCount    int    `json:"witness_count"`
}

// ListBackends returns a deduplicated summary of all backends that have
// submitted attestations, sorted alphabetically by backend name.
func (s *Store) ListBackends() []BackendSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byName := map[string]*BackendSummary{}
	for i := range s.entries {
		name := extractBackendName(s.entries[i].Report)
		if name == "" {
			name = "unknown"
		}
		bs, ok := byName[name]
		if !ok {
			bs = &BackendSummary{BackendName: name}
			byName[name] = bs
		}
		bs.TotalRuns++
		// Latest = highest sequence number wins (entries are append-order).
		bs.LatestEntryID = s.entries[i].EntryID
		bs.LatestRunAt = extractRunAt(s.entries[i].Report)
		bs.LatestLevel = extractConformantLevel(s.entries[i].Report)
		bs.LatestConformant = extractConformant(s.entries[i].Report)
		bs.WitnessCount = len(s.entries[i].WitnessCosignatures)
	}

	result := make([]BackendSummary, 0, len(byName))
	for _, bs := range byName {
		result = append(result, *bs)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].BackendName < result[j].BackendName
	})
	return result
}

// EntriesForBackend returns all entries for a given backend name, newest first.
func (s *Store) EntriesForBackend(backendName string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Entry
	for i := len(s.entries) - 1; i >= 0; i-- {
		name := extractBackendName(s.entries[i].Report)
		if name == "" {
			name = "unknown"
		}
		if name == backendName {
			e := s.entries[i]
			if len(e.WitnessCosignatures) > 0 {
				cs := make([]WitnessCosignature, len(e.WitnessCosignatures))
				copy(cs, e.WitnessCosignatures)
				e.WitnessCosignatures = cs
			}
			result = append(result, e)
		}
	}
	return result
}

// extractBackendName pulls the backend name from a report JSON blob.
// Checks report.backend.name first, then falls back to report.target.
func extractBackendName(report json.RawMessage) string {
	var r struct {
		Backend *struct {
			Name string `json:"name"`
		} `json:"backend"`
		Target string `json:"target"`
	}
	if json.Unmarshal(report, &r) != nil {
		return ""
	}
	if r.Backend != nil && r.Backend.Name != "" {
		return r.Backend.Name
	}
	return r.Target
}

func extractRunAt(report json.RawMessage) string {
	var r struct {
		RunAt string `json:"run_at"`
	}
	if json.Unmarshal(report, &r) != nil {
		return ""
	}
	return r.RunAt
}

// ExtractConformantLevel pulls the conformant_level from a report JSON blob.
func ExtractConformantLevel(report json.RawMessage) int {
	return extractConformantLevel(report)
}

// ExtractConformant pulls the conformant flag from a report JSON blob.
func ExtractConformant(report json.RawMessage) bool {
	return extractConformant(report)
}

// ExtractBackendName pulls the backend name from a report JSON blob.
func ExtractBackendName(report json.RawMessage) string {
	return extractBackendName(report)
}

// ExtractRunAt pulls the run_at timestamp from a report JSON blob.
func ExtractRunAt(report json.RawMessage) string {
	return extractRunAt(report)
}

func extractConformantLevel(report json.RawMessage) int {
	var r struct {
		ConformantLevel int `json:"conformant_level"`
	}
	if json.Unmarshal(report, &r) != nil {
		return -1
	}
	return r.ConformantLevel
}

func extractConformant(report json.RawMessage) bool {
	var r struct {
		Conformant bool `json:"conformant"`
	}
	json.Unmarshal(report, &r)
	return r.Conformant
}
