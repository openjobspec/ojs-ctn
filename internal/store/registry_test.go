package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestListEmpty(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	result := s.List(ListOptions{})
	if result.Total != 0 {
		t.Errorf("Total = %d, want 0", result.Total)
	}
	if len(result.Entries) != 0 {
		t.Errorf("Entries = %d, want 0", len(result.Entries))
	}
}

func TestListPagination(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	// Add 5 entries
	for i := 0; i < 5; i++ {
		report := json.RawMessage(`{"conformant":true,"conformant_level":` + itoa(i) + `,"backend":{"name":"test-backend"},"run_at":"2026-01-01T00:00:0` + itoa(i) + `Z"}`)
		_, err := s.Append(context.Background(), Submission{
			Report:             report,
			SubmitterSignature: "sig",
			SubmitterKeyID:     "key",
		})
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Page 1: offset=0, limit=2 → 2 newest entries
	result := s.List(ListOptions{Offset: 0, Limit: 2})
	if result.Total != 5 {
		t.Errorf("Total = %d, want 5", result.Total)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("Entries len = %d, want 2", len(result.Entries))
	}
	// Newest first: seq 5, then 4
	if result.Entries[0].SequenceNumber != 5 {
		t.Errorf("first entry seq = %d, want 5", result.Entries[0].SequenceNumber)
	}

	// Page 2: offset=2, limit=2
	result2 := s.List(ListOptions{Offset: 2, Limit: 2})
	if len(result2.Entries) != 2 {
		t.Fatalf("Page 2 Entries len = %d, want 2", len(result2.Entries))
	}
	if result2.Entries[0].SequenceNumber != 3 {
		t.Errorf("page 2 first entry seq = %d, want 3", result2.Entries[0].SequenceNumber)
	}

	// Beyond range
	result3 := s.List(ListOptions{Offset: 10, Limit: 2})
	if len(result3.Entries) != 0 {
		t.Errorf("beyond range Entries len = %d, want 0", len(result3.Entries))
	}
}

func TestListBackends(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	addEntry(t, s, "redis-backend", 4, true)
	addEntry(t, s, "redis-backend", 3, true)
	addEntry(t, s, "postgres-backend", 2, true)

	backends := s.ListBackends()
	if len(backends) != 2 {
		t.Fatalf("ListBackends = %d, want 2", len(backends))
	}

	// Alphabetical order
	if backends[0].BackendName != "postgres-backend" {
		t.Errorf("first backend = %q, want postgres-backend", backends[0].BackendName)
	}
	if backends[0].TotalRuns != 1 {
		t.Errorf("postgres TotalRuns = %d, want 1", backends[0].TotalRuns)
	}
	if backends[1].BackendName != "redis-backend" {
		t.Errorf("second backend = %q, want redis-backend", backends[1].BackendName)
	}
	if backends[1].TotalRuns != 2 {
		t.Errorf("redis TotalRuns = %d, want 2", backends[1].TotalRuns)
	}
}

func TestEntriesForBackend(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	addEntry(t, s, "redis-backend", 4, true)
	addEntry(t, s, "redis-backend", 3, true)
	addEntry(t, s, "postgres-backend", 2, true)

	entries := s.EntriesForBackend("redis-backend")
	if len(entries) != 2 {
		t.Fatalf("EntriesForBackend = %d, want 2", len(entries))
	}
	// Newest first
	if entries[0].SequenceNumber != 2 {
		t.Errorf("first entry seq = %d, want 2", entries[0].SequenceNumber)
	}

	// Unknown backend
	entries = s.EntriesForBackend("nonexistent")
	if len(entries) != 0 {
		t.Errorf("nonexistent backend = %d entries, want 0", len(entries))
	}
}

func TestExtractBackendName(t *testing.T) {
	tests := []struct {
		name   string
		report string
		want   string
	}{
		{"with backend.name", `{"backend":{"name":"redis"}}`, "redis"},
		{"fallback to target", `{"target":"http://localhost:8080"}`, "http://localhost:8080"},
		{"empty", `{}`, ""},
		{"invalid json", `invalid`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBackendName(json.RawMessage(tt.report))
			if got != tt.want {
				t.Errorf("extractBackendName = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractConformantLevel(t *testing.T) {
	got := ExtractConformantLevel(json.RawMessage(`{"conformant_level":3}`))
	if got != 3 {
		t.Errorf("ExtractConformantLevel = %d, want 3", got)
	}
}

func TestExtractConformant(t *testing.T) {
	if !ExtractConformant(json.RawMessage(`{"conformant":true}`)) {
		t.Error("ExtractConformant(true) = false")
	}
	if ExtractConformant(json.RawMessage(`{"conformant":false}`)) {
		t.Error("ExtractConformant(false) = true")
	}
}

// --- helpers ---

func openTempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func addEntry(t *testing.T, s *Store, backendName string, level int, conformant bool) {
	t.Helper()
	report, _ := json.Marshal(map[string]any{
		"backend":          map[string]any{"name": backendName},
		"conformant":       conformant,
		"conformant_level": level,
		"run_at":           "2026-04-18T12:00:00Z",
	})
	_, err := s.Append(context.Background(), Submission{
		Report:             report,
		SubmitterSignature: "sig",
		SubmitterKeyID:     "key",
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
}

// itoa is a local helper to avoid importing strconv just for test data.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 4)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func init() {
	// Ensure temp dirs are cleaned up
	_ = os.MkdirAll(os.TempDir(), 0755)
}

func TestListDefaultLimit(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	// Add 3 entries
	for i := 0; i < 3; i++ {
		addEntry(t, s, "backend-"+itoa(i), i, true)
	}

	result := s.List(ListOptions{Limit: 0})
	if result.Limit != 50 {
		t.Errorf("Limit = %d, want 50 (default)", result.Limit)
	}
	if len(result.Entries) != 3 {
		t.Errorf("Entries = %d, want 3", len(result.Entries))
	}
}

func TestListMaxLimit(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	addEntry(t, s, "test-backend", 1, true)

	result := s.List(ListOptions{Limit: 5000})
	if result.Limit != 1000 {
		t.Errorf("Limit = %d, want 1000 (capped)", result.Limit)
	}
}

func TestListNegativeOffset(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	addEntry(t, s, "test-backend", 1, true)

	result := s.List(ListOptions{Offset: -5})
	if result.Offset != 0 {
		t.Errorf("Offset = %d, want 0 (clamped)", result.Offset)
	}
	if len(result.Entries) != 1 {
		t.Errorf("Entries = %d, want 1", len(result.Entries))
	}
}

func TestEntriesForBackend_MultipleRuns(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()

	addEntry(t, s, "multi-backend", 1, true)
	addEntry(t, s, "multi-backend", 2, true)
	addEntry(t, s, "multi-backend", 3, true)
	addEntry(t, s, "other-backend", 4, true)

	entries := s.EntriesForBackend("multi-backend")
	if len(entries) != 3 {
		t.Fatalf("EntriesForBackend = %d, want 3", len(entries))
	}
	// Newest first: sequence numbers should be descending
	for i := 0; i < len(entries)-1; i++ {
		if entries[i].SequenceNumber <= entries[i+1].SequenceNumber {
			t.Errorf("entry[%d].seq=%d should be > entry[%d].seq=%d (newest first)",
				i, entries[i].SequenceNumber, i+1, entries[i+1].SequenceNumber)
		}
	}
}

func TestExtractRunAt_MissingField(t *testing.T) {
	got := ExtractRunAt(json.RawMessage(`{}`))
	if got != "" {
		t.Errorf("ExtractRunAt({}) = %q, want empty string", got)
	}
}

func TestExtractBackendName_NestedPath(t *testing.T) {
	// When backend.name is absent, should fall back to target
	report := json.RawMessage(`{"target":"http://redis:6379"}`)
	got := ExtractBackendName(report)
	if got != "http://redis:6379" {
		t.Errorf("ExtractBackendName = %q, want http://redis:6379", got)
	}
}
