// Package api exposes the CTN HTTP surface defined in
// ojs-ctn/docs/design.md (P1 subset + P2 registry).
//
//	POST /v1/submissions   - append a new entry
//	GET  /v1/entries/:id   - retrieve a logged entry
//	GET  /v1/log/head      - current ledger head
//	GET  /v1/registry      - list all attestations (paginated)
//	GET  /v1/registry/backends        - list backend summaries
//	GET  /v1/registry/backends/:name  - entries for a backend
//	GET  /v1/badges/:backend.svg      - SVG badge for a backend
//	GET  /healthz          - liveness probe
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/openjobspec/ojs-ctn/internal/attestlog"
	"github.com/openjobspec/ojs-ctn/internal/metrics"
	"github.com/openjobspec/ojs-ctn/internal/store"
	"github.com/openjobspec/ojs-ctn/internal/witness"
)

// Server is the HTTP handler bundle.
type Server struct {
	Store       *store.Store
	Witness     *witness.Registry
	Revocations *attestlog.RevocationLog
	Metrics     *metrics.Counters
}

// Routes returns an http.Handler covering the P1 surface plus P2 cosig and registry.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/log/head", s.handleHead)
	mux.HandleFunc("/v1/submissions", s.handleSubmissions)
	// Registry endpoints (P2)
	mux.HandleFunc("/v1/registry/backends/", s.handleRegistryBackend)
	mux.HandleFunc("/v1/registry/backends", s.handleRegistryBackends)
	mux.HandleFunc("/v1/registry", s.handleRegistry)
	mux.HandleFunc("/v1/badges/", s.handleBadge)
	// Witness management (P2)
	mux.HandleFunc("/v1/witnesses/register", s.handleWitnessRegister)
	mux.HandleFunc("/v1/witnesses/", s.handleWitnessDetail)
	mux.HandleFunc("/v1/witnesses", s.handleWitnessList)
	// "/v1/entries/" is a prefix; the trailing path segment is the entry ID,
	// optionally followed by "/witness", "/revoke", or "/status" for sub-resources.
	mux.HandleFunc("/v1/entries/", s.handleEntry)
	// Metrics endpoint
	mux.HandleFunc("/v1/metrics", s.handleMetrics)
	return logging(mux)
}

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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		// Best-effort: cannot recover after WriteHeader.
		_ = err
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Minimal access log; structured logging lives in P2.
		h.ServeHTTP(w, r)
	})
}

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
