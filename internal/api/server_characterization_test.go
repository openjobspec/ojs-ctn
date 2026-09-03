package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openjobspec/ojs-ctn/internal/attestlog"
	"github.com/openjobspec/ojs-ctn/internal/metrics"
	"github.com/openjobspec/ojs-ctn/internal/store"
	"github.com/openjobspec/ojs-ctn/internal/witness"
)

func TestRouteCompositionCharacterization(t *testing.T) {
	handler := newCharacterizationHandler(t)
	tests := []struct {
		name        string
		method      string
		path        string
		status      int
		contentType string
		body        string
	}{
		{"health accepts post", http.MethodPost, "/healthz", http.StatusOK, "application/json", "{\"entries\":0,\"status\":\"ok\"}\n"},
		{"head", http.MethodDelete, "/v1/log/head", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"submissions", http.MethodGet, "/v1/submissions", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"registry", http.MethodPost, "/v1/registry", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"registry backends", http.MethodPost, "/v1/registry/backends", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"registry backend prefix", http.MethodGet, "/v1/registry/backends/", http.StatusBadRequest, "application/json", "{\"error\":\"missing backend name\"}\n"},
		{"badge", http.MethodPost, "/v1/badges/backend.svg", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"witness registration", http.MethodGet, "/v1/witnesses/register", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"witness detail prefix", http.MethodPost, "/v1/witnesses/missing/stats", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"witness list", http.MethodDelete, "/v1/witnesses", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"entry prefix", http.MethodGet, "/v1/entries/", http.StatusBadRequest, "application/json", "{\"error\":\"missing entry id\"}\n"},
		{"entry witness", http.MethodGet, "/v1/entries/id/witness", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"entry revoke", http.MethodGet, "/v1/entries/id/revoke", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"entry status", http.MethodPost, "/v1/entries/id/status", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"entry unknown subresource", http.MethodGet, "/v1/entries/id/unknown", http.StatusNotFound, "application/json", "{\"error\":\"unknown sub-resource\"}\n"},
		{"metrics", http.MethodPost, "/v1/metrics", http.StatusMethodNotAllowed, "application/json", "{\"error\":\"method not allowed\"}\n"},
		{"unknown route", http.MethodGet, "/not-a-route", http.StatusNotFound, "text/plain; charset=utf-8", "404 page not found\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serve(handler, tt.method, tt.path, nil)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if got := rec.Header().Get("Content-Type"); got != tt.contentType {
				t.Fatalf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if got := rec.Body.String(); got != tt.body {
				t.Fatalf("body = %q, want %q", got, tt.body)
			}
		})
	}
}

func TestRequestBodyLimitsCharacterization(t *testing.T) {
	handler := newCharacterizationHandler(t)
	tests := []struct {
		name   string
		path   string
		limit  int
		status int
		body   string
	}{
		{"submission at limit", "/v1/submissions", 4 * 1024 * 1024, http.StatusBadRequest, ""},
		{"submission over limit", "/v1/submissions", 4*1024*1024 + 1, http.StatusRequestEntityTooLarge, "{\"error\":\"request body too large\"}\n"},
		{"cosignature at limit", "/v1/entries/id/witness", 64 * 1024, http.StatusBadRequest, ""},
		{"cosignature over limit", "/v1/entries/id/witness", 64*1024 + 1, http.StatusRequestEntityTooLarge, "{\"error\":\"request body too large\"}\n"},
		{"revocation at limit", "/v1/entries/id/revoke", 64 * 1024, http.StatusBadRequest, ""},
		{"revocation over limit", "/v1/entries/id/revoke", 64*1024 + 1, http.StatusRequestEntityTooLarge, "{\"error\":\"request body too large\"}\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.NewReader(strings.Repeat("x", tt.limit))
			rec := serve(handler, http.MethodPost, tt.path, body)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, tt.status, rec.Body.String())
			}
			if tt.body != "" && rec.Body.String() != tt.body {
				t.Fatalf("body = %q, want %q", rec.Body.String(), tt.body)
			}
		})
	}
}

func newCharacterizationHandler(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return (&Server{
		Store:       st,
		Witness:     witness.NewRegistry(witness.Config{}),
		Revocations: attestlog.NewRevocationLog(),
		Metrics:     metrics.NewCounters(),
	}).Routes()
}

func serve(handler http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
