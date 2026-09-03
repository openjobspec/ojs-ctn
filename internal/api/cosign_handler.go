package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// handleWitness accepts a cosignature for an existing entry.
//
// Body: {"witness_key_id":"did:web:...","witness_signature":"base64..."}
//
// The signature MUST be ed25519 over the canonical JSON of the entry's
// `report` field — the same bytes the submitter signed. ctn-witness
// computes this client-side; the server stores it opaquely and trusts
// ctn-verify (or any downstream auditor) to re-verify with the
// witness's pinned public key.
func (s *Server) handleWitness(w http.ResponseWriter, r *http.Request, entryID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var req struct {
		WitnessKeyID     string `json:"witness_key_id"`
		WitnessSignature string `json:"witness_signature"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	entry, err := s.Store.Cosign(r.Context(), entryID, req.WitnessKeyID, req.WitnessSignature)
	if err != nil {
		s.incErrors()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.incWitnesses()
	writeJSON(w, http.StatusCreated, entry)
}
