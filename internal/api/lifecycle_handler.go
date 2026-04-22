package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/openjobspec/ojs-ctn/internal/attestlog"
)

// handleRevoke revokes an attestation entry.
//
// POST /v1/entries/{id}/revoke — body: {"reason":"..."}
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, entryID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Revocations == nil {
		s.incErrors()
		writeError(w, http.StatusServiceUnavailable, "revocation log not configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		s.incErrors()
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.incErrors()
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	// Verify entry exists.
	if _, err := s.Store.Get(r.Context(), entryID); err != nil {
		s.incErrors()
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err := s.Revocations.Revoke(entryID, req.Reason); err != nil {
		s.incErrors()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "entry_id": entryID})
}

// handleStatus returns the lifecycle status of an attestation entry.
//
// GET /v1/entries/{id}/status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, entryID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	entry, err := s.Store.Get(r.Context(), entryID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	checker := attestlog.StatusChecker{
		Config:      attestlog.DefaultDecayConfig(),
		Revocations: s.Revocations,
	}
	s.incQueries()
	writeJSON(w, http.StatusOK, checker.Check(entry))
}
