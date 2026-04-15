package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/openjobspec/ojs-ctn/internal/badge"
	"github.com/openjobspec/ojs-ctn/internal/store"
)

func (s *Server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.incQueries()
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	result := s.Store.List(store.ListOptions{Offset: offset, Limit: limit})
	result.Entries = applyRegistryFilters(result.Entries, r.URL.Query())
	writeJSON(w, http.StatusOK, result)
}

// registryFilters holds the parsed query-string filters for the
// registry list endpoint.
type registryFilters struct {
	backend string
	level   int // -1 = no filter
	since   string
}

func parseRegistryFilters(q interface{ Get(string) string }) registryFilters {
	f := registryFilters{
		backend: q.Get("backend"),
		since:   q.Get("since"),
		level:   -1,
	}
	if lv := q.Get("level"); lv != "" {
		f.level, _ = strconv.Atoi(lv)
	}
	return f
}

func applyRegistryFilters(entries []store.Entry, q interface{ Get(string) string }) []store.Entry {
	f := parseRegistryFilters(q)
	if f.backend == "" && f.level < 0 && f.since == "" {
		return entries
	}
	filtered := make([]store.Entry, 0, len(entries))
	for _, e := range entries {
		if f.backend != "" && store.ExtractBackendName(e.Report) != f.backend {
			continue
		}
		if f.level >= 0 && store.ExtractConformantLevel(e.Report) < f.level {
			continue
		}
		if f.since != "" && store.ExtractRunAt(e.Report) < f.since {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func (s *Server) handleRegistryBackends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	backends := s.Store.ListBackends()
	writeJSON(w, http.StatusOK, map[string]any{"backends": backends})
}

func (s *Server) handleRegistryBackend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/registry/backends/")
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing backend name")
		return
	}
	entries := s.Store.EntriesForBackend(name)
	writeJSON(w, http.StatusOK, map[string]any{"backend": name, "entries": entries, "total": len(entries)})
}

func (s *Server) handleBadge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/badges/")
	name = strings.TrimSuffix(name, ".svg")
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing backend name")
		return
	}

	entries := s.Store.EntriesForBackend(name)
	level := -1
	conformant := false
	if len(entries) > 0 {
		level = store.ExtractConformantLevel(entries[0].Report)
		conformant = store.ExtractConformant(entries[0].Report)
	}

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-cache, max-age=300")
	w.WriteHeader(http.StatusOK)
	s.incBadges()
	fmt.Fprint(w, badge.SVG(name, level, conformant))
}
