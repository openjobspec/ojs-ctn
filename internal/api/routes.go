package api

import "net/http"

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

func logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Minimal access log; structured logging lives in P2.
		h.ServeHTTP(w, r)
	})
}
