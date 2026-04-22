package store

import (
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.list(opts)
}

func (i *ledgerIndex) list(opts ListOptions) ListResult {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 1000 {
		opts.Limit = 1000
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	total := len(i.entries)
	if opts.Offset >= total {
		return ListResult{Entries: []Entry{}, Total: total, Offset: opts.Offset, Limit: opts.Limit}
	}

	// Reverse order (newest first) without modifying the append-order index.
	end := total - opts.Offset
	start := end - opts.Limit
	if start < 0 {
		start = 0
	}
	slice := make([]Entry, end-start)
	for position, j := end-1, 0; position >= start; position-- {
		slice[j] = copyEntry(i.entries[position])
		j++
	}

	return ListResult{Entries: slice, Total: total, Offset: opts.Offset, Limit: opts.Limit}
}

// BackendSummary aggregates attestation info for a single backend.
type BackendSummary struct {
	BackendName      string `json:"backend_name"`
	LatestEntryID    string `json:"latest_entry_id"`
	LatestLevel      int    `json:"latest_level"`
	LatestConformant bool   `json:"latest_conformant"`
	LatestRunAt      string `json:"latest_run_at"`
	TotalRuns        int    `json:"total_runs"`
	WitnessCount     int    `json:"witness_count"`
}

// ListBackends returns a deduplicated summary of all backends that have
// submitted attestations, sorted alphabetically by backend name.
func (s *Store) ListBackends() []BackendSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.listBackends()
}

func (i *ledgerIndex) listBackends() []BackendSummary {
	byName := map[string]*BackendSummary{}
	for position := range i.entries {
		report := decodeReportProjection(i.entries[position].Report)
		name := report.backendName()
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
		bs.LatestEntryID = i.entries[position].EntryID
		bs.LatestRunAt = report.runTimestamp()
		bs.LatestLevel = report.conformanceLevel()
		bs.LatestConformant = report.isConformant()
		bs.WitnessCount = len(i.entries[position].WitnessCosignatures)
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
	return s.index.entriesForBackend(backendName)
}

func (i *ledgerIndex) entriesForBackend(backendName string) []Entry {
	var result []Entry
	for position := len(i.entries) - 1; position >= 0; position-- {
		name := decodeReportProjection(i.entries[position].Report).backendName()
		if name == "" {
			name = "unknown"
		}
		if name == backendName {
			result = append(result, copyEntry(i.entries[position]))
		}
	}
	return result
}
