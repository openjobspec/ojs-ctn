package api

import (
	"net/http"
	"strings"
)

func (s *Server) handleEntry(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/entries/")
	if rest == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}
	// Sub-resource dispatch: POST /v1/entries/{id}/witness, /revoke, GET /status
	if idx := strings.Index(rest, "/"); idx >= 0 {
		id := rest[:idx]
		sub := rest[idx+1:]
		switch sub {
		case "witness":
			s.handleWitness(w, r, id)
		case "revoke":
			s.handleRevoke(w, r, id)
		case "status":
			s.handleStatus(w, r, id)
		default:
			writeError(w, http.StatusNotFound, "unknown sub-resource")
		}
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := rest
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}
	entry, err := s.Store.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.incQueries()
	writeJSON(w, http.StatusOK, entry)
}
