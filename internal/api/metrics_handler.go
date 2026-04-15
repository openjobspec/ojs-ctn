package api

import (
	"net/http"
)

// handleMetrics returns a JSON snapshot of in-memory counters.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Metrics == nil {
		writeJSON(w, http.StatusOK, map[string]int64{})
		return
	}
	writeJSON(w, http.StatusOK, s.Metrics.Snapshot())
}

// incSubmissions safely increments the submissions counter if configured.
func (s *Server) incSubmissions() {
	if s.Metrics != nil {
		s.Metrics.IncSubmissions()
	}
}

// incQueries safely increments the queries counter if configured.
func (s *Server) incQueries() {
	if s.Metrics != nil {
		s.Metrics.IncQueries()
	}
}

// incBadges safely increments the badges counter if configured.
func (s *Server) incBadges() {
	if s.Metrics != nil {
		s.Metrics.IncBadges()
	}
}

// incWitnesses safely increments the witnesses counter if configured.
func (s *Server) incWitnesses() {
	if s.Metrics != nil {
		s.Metrics.IncWitnesses()
	}
}

// incErrors safely increments the errors counter if configured.
func (s *Server) incErrors() {
	if s.Metrics != nil {
		s.Metrics.IncErrors()
	}
}
