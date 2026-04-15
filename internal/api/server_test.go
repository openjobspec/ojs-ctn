package api

import (
	"bytes"
	"context"
	"encoding/json"
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

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	wr := witness.NewRegistry(witness.Config{})
	srv := httptest.NewServer((&Server{
		Store:       st,
		Witness:     wr,
		Revocations: attestlog.NewRevocationLog(),
		Metrics:     metrics.NewCounters(),
	}).Routes())
	t.Cleanup(srv.Close)
	return srv
}

func TestSubmissionFlow(t *testing.T) {
	srv := newTestServer(t)

	body := []byte(`{
		"report": {"test_suite_version":"x","conformant":true},
		"submitter_signature": "deadbeef",
		"submitter_key_id": "did:web:example.com:keys:postgres-2026"
	}`)

	resp, err := http.Post(srv.URL+"/v1/submissions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var entry struct {
		EntryID        string `json:"entry_id"`
		SequenceNumber uint64 `json:"sequence_number"`
		ReportSHA256   string `json:"report_sha256"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		t.Fatal(err)
	}
	if entry.EntryID == "" || entry.SequenceNumber != 1 || entry.ReportSHA256 == "" {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	// Get the entry back.
	r2, err := http.Get(srv.URL + "/v1/entries/" + entry.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("entry GET expected 200, got %d", r2.StatusCode)
	}

	// Head reflects the submission.
	r3, err := http.Get(srv.URL + "/v1/log/head")
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Body.Close()
	var head struct {
		SequenceNumber uint64 `json:"sequence_number"`
		LastEntryID    string `json:"last_entry_id"`
	}
	if err := json.NewDecoder(r3.Body).Decode(&head); err != nil {
		t.Fatal(err)
	}
	if head.SequenceNumber != 1 || head.LastEntryID != entry.EntryID {
		t.Errorf("head mismatch: %+v vs entry %s", head, entry.EntryID)
	}
}

func TestSubmissionInvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Post(srv.URL+"/v1/submissions", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestEntryNotFound(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/v1/entries/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, srv.URL+"/v1/log/head", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func submitReport(t *testing.T, srvURL, backendName string, level int, conformant bool) string {
	t.Helper()
	report, _ := json.Marshal(map[string]any{
		"backend":          map[string]any{"name": backendName},
		"conformant":       conformant,
		"conformant_level": level,
		"run_at":           "2026-04-18T12:00:00Z",
	})
	// Build submission with report as raw JSON (not double-encoded).
	sub := `{"report":` + string(report) + `,"submitter_signature":"sig","submitter_key_id":"key1"}`
	resp, err := http.Post(srvURL+"/v1/submissions", "application/json", strings.NewReader(sub))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("submit: expected 201, got %d", resp.StatusCode)
	}
	var entry struct{ EntryID string `json:"entry_id"` }
	json.NewDecoder(resp.Body).Decode(&entry)
	return entry.EntryID
}

func TestRegistryList(t *testing.T) {
	srv := newTestServer(t)

	submitReport(t, srv.URL, "redis", 4, true)
	submitReport(t, srv.URL, "postgres", 3, true)

	resp, err := http.Get(srv.URL + "/v1/registry?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("registry: expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Entries []json.RawMessage `json:"entries"`
		Total   int               `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Total != 2 {
		t.Errorf("registry total = %d, want 2", result.Total)
	}
	if len(result.Entries) != 2 {
		t.Errorf("registry entries = %d, want 2", len(result.Entries))
	}
}

func TestRegistryBackends(t *testing.T) {
	srv := newTestServer(t)

	submitReport(t, srv.URL, "redis", 4, true)
	submitReport(t, srv.URL, "redis", 3, true)
	submitReport(t, srv.URL, "postgres", 2, true)

	resp, err := http.Get(srv.URL + "/v1/registry/backends")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backends: expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Backends []struct {
			BackendName string `json:"backend_name"`
			TotalRuns   int    `json:"total_runs"`
		} `json:"backends"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(result.Backends))
	}
}

func TestRegistryBackendEntries(t *testing.T) {
	srv := newTestServer(t)

	submitReport(t, srv.URL, "redis", 4, true)
	submitReport(t, srv.URL, "postgres", 2, true)

	resp, err := http.Get(srv.URL + "/v1/registry/backends/redis")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backend entries: expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Backend string            `json:"backend"`
		Entries []json.RawMessage `json:"entries"`
		Total   int               `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Backend != "redis" {
		t.Errorf("backend = %q, want redis", result.Backend)
	}
	if result.Total != 1 {
		t.Errorf("entries total = %d, want 1", result.Total)
	}
}

func TestBadgeSVG(t *testing.T) {
	srv := newTestServer(t)

	submitReport(t, srv.URL, "redis", 4, true)

	resp, err := http.Get(srv.URL + "/v1/badges/redis.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("badge: expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "image/svg+xml" {
		t.Errorf("Content-Type = %q, want image/svg+xml", ct)
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	svg := buf.String()
	if !strings.Contains(svg, "<svg") {
		t.Error("badge should be SVG")
	}
	if !strings.Contains(svg, "L4 Advanced") {
		t.Error("badge should show L4 Advanced for conformant level 4")
	}
}

func TestBadgeUnknownBackend(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/v1/badges/nonexistent.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("badge unknown: expected 200, got %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "non-conformant") {
		t.Error("unknown backend badge should show non-conformant")
	}
}

func TestWitnessRegisterAndList(t *testing.T) {
	srv := newTestServer(t)

	body := `{"id":"w1","org":"acme","endpoint":"https://w1.example.com","key_id":"key1"}`
	resp, err := http.Post(srv.URL+"/v1/witnesses/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}

	// List witnesses
	resp2, err := http.Get(srv.URL + "/v1/witnesses")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", resp2.StatusCode)
	}
	var result struct {
		Witnesses []json.RawMessage `json:"witnesses"`
	}
	json.NewDecoder(resp2.Body).Decode(&result)
	if len(result.Witnesses) != 1 {
		t.Errorf("witnesses = %d, want 1", len(result.Witnesses))
	}
}

func TestWitnessStats(t *testing.T) {
	srv := newTestServer(t)

	body := `{"id":"w1","org":"acme","endpoint":"https://w1.example.com","key_id":"key1"}`
	http.Post(srv.URL+"/v1/witnesses/register", "application/json", strings.NewReader(body))

	resp, err := http.Get(srv.URL + "/v1/witnesses/w1/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats: expected 200, got %d", resp.StatusCode)
	}
}

func TestWitnessNotFound(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/v1/witnesses/nonexistent/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestRegistryFiltering(t *testing.T) {
	srv := newTestServer(t)

	submitReport(t, srv.URL, "redis", 4, true)
	submitReport(t, srv.URL, "postgres", 2, true)
	submitReport(t, srv.URL, "redis", 3, true)

	// Filter by backend
	resp, err := http.Get(srv.URL + "/v1/registry?limit=100&backend=redis")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Entries []json.RawMessage `json:"entries"`
		Total   int               `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Entries) != 2 {
		t.Errorf("backend=redis: got %d entries, want 2", len(result.Entries))
	}

	// Filter by level
	resp2, err := http.Get(srv.URL + "/v1/registry?limit=100&level=4")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var result2 struct {
		Entries []json.RawMessage `json:"entries"`
	}
	json.NewDecoder(resp2.Body).Decode(&result2)
	if len(result2.Entries) != 1 {
		t.Errorf("level=4: got %d entries, want 1", len(result2.Entries))
	}
}

func TestRegistryPaginationBounds(t *testing.T) {
	srv := newTestServer(t)

	submitReport(t, srv.URL, "redis", 4, true)
	submitReport(t, srv.URL, "postgres", 3, true)

	// Offset beyond total — should return empty entries.
	resp, err := http.Get(srv.URL + "/v1/registry?offset=100&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Entries []json.RawMessage `json:"entries"`
		Total   int               `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Entries) != 0 {
		t.Errorf("offset beyond total: got %d entries, want 0", len(result.Entries))
	}
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}

	// Negative offset should be clamped to 0.
	resp2, err := http.Get(srv.URL + "/v1/registry?offset=-5&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for negative offset, got %d", resp2.StatusCode)
	}
	var result2 struct {
		Entries []json.RawMessage `json:"entries"`
	}
	json.NewDecoder(resp2.Body).Decode(&result2)
	if len(result2.Entries) != 2 {
		t.Errorf("negative offset: got %d entries, want 2", len(result2.Entries))
	}

	// limit=0 should default to 50.
	resp3, err := http.Get(srv.URL + "/v1/registry?limit=0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for limit=0, got %d", resp3.StatusCode)
	}
	var result3 struct {
		Entries []json.RawMessage `json:"entries"`
		Limit   int               `json:"limit"`
	}
	json.NewDecoder(resp3.Body).Decode(&result3)
	if result3.Limit != 50 {
		t.Errorf("limit=0 should clamp to 50, got %d", result3.Limit)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv := newTestServer(t)

	// Submit something so counters are non-zero.
	submitReport(t, srv.URL, "redis", 4, true)

	resp, err := http.Get(srv.URL + "/v1/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: expected 200, got %d", resp.StatusCode)
	}
	var counters map[string]int64
	if err := json.NewDecoder(resp.Body).Decode(&counters); err != nil {
		t.Fatalf("metrics: invalid JSON: %v", err)
	}
	if _, ok := counters["submissions"]; !ok {
		t.Error("metrics should contain 'submissions' counter")
	}
	if counters["submissions"] < 1 {
		t.Errorf("submissions counter = %d, want >= 1", counters["submissions"])
	}
}

func TestStatusEndpoint(t *testing.T) {
	srv := newTestServer(t)

	entryID := submitReport(t, srv.URL, "redis", 4, true)

	resp, err := http.Get(srv.URL + "/v1/entries/" + entryID + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", resp.StatusCode)
	}
	var status struct {
		EntryID string `json:"entry_id"`
		Status  string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.Status != "active" {
		t.Errorf("status = %q, want active", status.Status)
	}
	if status.EntryID != entryID {
		t.Errorf("entry_id = %q, want %q", status.EntryID, entryID)
	}
}

func TestRevokeAndStatus(t *testing.T) {
	srv := newTestServer(t)

	entryID := submitReport(t, srv.URL, "redis", 4, true)

	// Revoke the entry.
	revokeBody := `{"reason":"compromised key"}`
	resp, err := http.Post(srv.URL+"/v1/entries/"+entryID+"/revoke", "application/json", strings.NewReader(revokeBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", resp.StatusCode)
	}

	// Check status shows revoked.
	resp2, err := http.Get(srv.URL + "/v1/entries/" + entryID + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status after revoke: expected 200, got %d", resp2.StatusCode)
	}
	var status struct {
		EntryID string `json:"entry_id"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.Status != "revoked" {
		t.Errorf("status = %q, want revoked", status.Status)
	}
	if status.Reason != "compromised key" {
		t.Errorf("reason = %q, want 'compromised key'", status.Reason)
	}
}

func TestRevokeMissingReason(t *testing.T) {
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	// Revoke with empty reason — attestlog.Revoke requires a reason,
	// so this should fail with 400.
	revokeBody := `{"reason":""}`
	resp, err := http.Post(srv.URL+"/v1/entries/"+entryID+"/revoke", "application/json", strings.NewReader(revokeBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoke empty reason: expected 400, got %d", resp.StatusCode)
	}
}

func TestRevokeNonexistentEntry(t *testing.T) {
	srv := newTestServer(t)

	revokeBody := `{"reason":"test revocation"}`
	resp, err := http.Post(srv.URL+"/v1/entries/nonexistent-id/revoke", "application/json", strings.NewReader(revokeBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke nonexistent: expected 404, got %d", resp.StatusCode)
	}
}

func TestStatusDecayed(t *testing.T) {
	// Submit an entry and check its initial status is active.
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	resp, err := http.Get(srv.URL + "/v1/entries/" + entryID + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", resp.StatusCode)
	}
	var status struct {
		EntryID string `json:"entry_id"`
		Status  string `json:"status"`
		Age     string `json:"age"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	// A freshly submitted entry should be "active".
	if status.Status != "active" {
		t.Errorf("status = %q, want active", status.Status)
	}
	if status.Age == "" {
		t.Error("age should be non-empty")
	}
}

func TestMetricsAfterOperations(t *testing.T) {
	srv := newTestServer(t)

	// Submit 3 entries.
	id1 := submitReport(t, srv.URL, "redis", 4, true)
	submitReport(t, srv.URL, "postgres", 3, true)
	submitReport(t, srv.URL, "nats", 2, true)

	// Query 2 entries.
	http.Get(srv.URL + "/v1/entries/" + id1)
	http.Get(srv.URL + "/v1/registry?limit=10")

	resp, err := http.Get(srv.URL + "/v1/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: expected 200, got %d", resp.StatusCode)
	}
	var counters map[string]int64
	if err := json.NewDecoder(resp.Body).Decode(&counters); err != nil {
		t.Fatal(err)
	}
	if counters["submissions"] != 3 {
		t.Errorf("submissions = %d, want 3", counters["submissions"])
	}
	// queries: 1 from GET entry + 1 from registry list = 2
	if counters["queries"] < 2 {
		t.Errorf("queries = %d, want >= 2", counters["queries"])
	}
}

func TestRegistryFilterByLevel(t *testing.T) {
	srv := newTestServer(t)

	submitReport(t, srv.URL, "redis", 4, true)
	submitReport(t, srv.URL, "postgres", 2, true)
	submitReport(t, srv.URL, "nats", 3, true)
	submitReport(t, srv.URL, "lite", 1, true)

	// Filter level=3 should return entries with level >= 3 (redis L4, nats L3)
	resp, err := http.Get(srv.URL + "/v1/registry?limit=100&level=3")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Entries []json.RawMessage `json:"entries"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Entries) != 2 {
		t.Errorf("level>=3: got %d entries, want 2", len(result.Entries))
	}

	// Filter level=4 should return only redis
	resp2, err := http.Get(srv.URL + "/v1/registry?limit=100&level=4")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var result2 struct {
		Entries []json.RawMessage `json:"entries"`
	}
	json.NewDecoder(resp2.Body).Decode(&result2)
	if len(result2.Entries) != 1 {
		t.Errorf("level>=4: got %d entries, want 1", len(result2.Entries))
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Status  string `json:"status"`
		Entries int    `json:"entries"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Status != "ok" {
		t.Errorf("status = %q, want ok", result.Status)
	}
}

func TestSubmissionEmptyReport(t *testing.T) {
	srv := newTestServer(t)
	body := `{"report":{},"submitter_signature":"sig","submitter_key_id":"key"}`
	resp, err := http.Post(srv.URL+"/v1/submissions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Empty report (as object {}) is 2 bytes and should still succeed as it's non-empty.
	// But a truly empty report (nil/null) should fail.
	body2 := `{"submitter_signature":"sig","submitter_key_id":"key"}`
	resp2, err := http.Post(srv.URL+"/v1/submissions", "application/json", strings.NewReader(body2))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("missing report: expected 400, got %d", resp2.StatusCode)
	}
}

func TestUnknownSubResource(t *testing.T) {
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	resp, err := http.Get(srv.URL + "/v1/entries/" + entryID + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown sub-resource: expected 404, got %d", resp.StatusCode)
	}
}

func TestStatusNonexistentEntry(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/v1/entries/nonexistent/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestCosignEntry(t *testing.T) {
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	cosignBody := `{"witness_key_id":"did:web:w1","witness_signature":"deadbeef"}`
	resp, err := http.Post(srv.URL+"/v1/entries/"+entryID+"/witness", "application/json", strings.NewReader(cosignBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("cosign: expected 201, got %d", resp.StatusCode)
	}
}

func TestBadgeNonConformant(t *testing.T) {
	srv := newTestServer(t)
	submitReport(t, srv.URL, "failing", 0, false)

	resp, err := http.Get(srv.URL + "/v1/badges/failing.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("badge: expected 200, got %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "non-conformant") {
		t.Error("badge should show non-conformant")
	}
}

func TestMethodNotAllowedOnVariousEndpoints(t *testing.T) {
	srv := newTestServer(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/registry"},
		{http.MethodPost, "/v1/registry/backends"},
		{http.MethodPost, "/v1/badges/test.svg"},
		{http.MethodDelete, "/v1/submissions"},
		{http.MethodPost, "/v1/metrics"},
		{http.MethodDelete, "/v1/witnesses"},
		{http.MethodGet, "/v1/witnesses/register"},
	}

	for _, ep := range endpoints {
		req, _ := http.NewRequestWithContext(context.Background(), ep.method, srv.URL+ep.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", ep.method, ep.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: expected 405, got %d", ep.method, ep.path, resp.StatusCode)
		}
	}
}

func TestWitnessRegisterInvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Post(srv.URL+"/v1/witnesses/register", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWitnessRegisterMissingFields(t *testing.T) {
	srv := newTestServer(t)
	// Missing org field
	body := `{"id":"w1","endpoint":"https://w1.example.com","key_id":"key1"}`
	resp, err := http.Post(srv.URL+"/v1/witnesses/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing org, got %d", resp.StatusCode)
	}
}

func TestRevokeMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/entries/"+entryID+"/revoke", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestRevokeInvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	resp, err := http.Post(srv.URL+"/v1/entries/"+entryID+"/revoke", "application/json", strings.NewReader("bad json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWitnessEntryMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/entries/"+entryID+"/witness", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestMetricsNilCounters(t *testing.T) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv := httptest.NewServer((&Server{
		Store:       st,
		Revocations: attestlog.NewRevocationLog(),
		Metrics:     nil, // no metrics configured
	}).Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var counters map[string]int64
	json.NewDecoder(resp.Body).Decode(&counters)
	if len(counters) != 0 {
		t.Errorf("nil metrics should return empty map, got %v", counters)
	}
}

func TestEntryMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	entryID := submitReport(t, srv.URL, "redis", 4, true)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, srv.URL+"/v1/entries/"+entryID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestRegistryBackendMissingName(t *testing.T) {
	srv := newTestServer(t)
	// Trailing slash but no name
	resp, err := http.Get(srv.URL + "/v1/registry/backends/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Should return the backend list or 400 depending on routing
	// The handler requires a name
}
