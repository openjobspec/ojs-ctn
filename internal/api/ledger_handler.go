package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openjobspec/ojs-ctn/internal/store"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "entries": s.Store.Count()})
}

func (s *Server) handleHead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.Store.Head(r.Context()))
}

func (s *Server) handleSubmissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024*1024))
	if err != nil {
		s.incErrors()
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var sub store.Submission
	if err := json.Unmarshal(body, &sub); err != nil {
		s.incErrors()
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if len(sub.Report) == 0 {
		s.incErrors()
		writeError(w, http.StatusBadRequest, "submission.report must not be empty")
		return
	}
	entry, err := s.Store.Append(r.Context(), sub)
	if err != nil {
		s.incErrors()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.incSubmissions()
	writeJSON(w, http.StatusCreated, entry)
}
