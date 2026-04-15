package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/openjobspec/ojs-ctn/internal/witness"
)

func (s *Server) handleWitnessRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Witness == nil {
		writeError(w, http.StatusServiceUnavailable, "witness registry not configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var wit witness.Witness
	if err := json.Unmarshal(body, &wit); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := s.Witness.Register(wit); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered", "id": wit.ID})
}

func (s *Server) handleWitnessList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Witness == nil {
		writeJSON(w, http.StatusOK, map[string]any{"witnesses": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"witnesses": s.Witness.List()})
}

func (s *Server) handleWitnessDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Witness == nil {
		writeError(w, http.StatusNotFound, "witness registry not configured")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/witnesses/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing witness id")
		return
	}
	// Handle /v1/witnesses/{id}/stats suffix
	id = strings.TrimSuffix(id, "/stats")
	stats, err := s.Witness.GetStats(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
