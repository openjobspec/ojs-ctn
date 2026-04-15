package attestlog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewReceiptSubmitter(t *testing.T) {
	s := NewReceiptSubmitter("http://localhost:9090")
	if s.ctnEndpoint != "http://localhost:9090" {
		t.Fatalf("expected endpoint http://localhost:9090, got %s", s.ctnEndpoint)
	}
	if s.httpClient != http.DefaultClient {
		t.Fatal("expected default HTTP client")
	}
}

func TestSubmitValidation(t *testing.T) {
	s := NewReceiptSubmitter("http://localhost:9090")
	ctx := context.Background()

	tests := []struct {
		name    string
		receipt Receipt
		wantErr string
	}{
		{
			name:    "empty job_id",
			receipt: Receipt{ArgsHash: "abc", Signature: "sig", KeyID: "k1"},
			wantErr: "job_id required",
		},
		{
			name:    "empty args_hash",
			receipt: Receipt{JobID: "j1", Signature: "sig", KeyID: "k1"},
			wantErr: "args_hash required",
		},
		{
			name:    "empty signature",
			receipt: Receipt{JobID: "j1", ArgsHash: "abc", KeyID: "k1"},
			wantErr: "signature required",
		},
		{
			name:    "empty key_id",
			receipt: Receipt{JobID: "j1", ArgsHash: "abc", Signature: "sig"},
			wantErr: "key_id required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Submit(ctx, tt.receipt)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); got == "" || !contains(got, tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, got)
			}
		})
	}
}

func TestSubmitSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/submissions" {
			t.Errorf("expected /v1/submissions, got %s", r.URL.Path)
		}

		var receipt Receipt
		if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(SubmitResult{
			EntryID:      "entry-001",
			ReportSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		})
	}))
	defer srv.Close()

	s := NewReceiptSubmitter(srv.URL)
	ctx := context.Background()

	result, err := s.Submit(ctx, Receipt{
		JobID:      "job-123",
		ArgsHash:   "abc123",
		ResultHash: "def456",
		Quote:      json.RawMessage(`{"type":"none"}`),
		Signature:  "sig-hex",
		KeyID:      "key-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.EntryID != "entry-001" {
		t.Errorf("expected entry-001, got %s", result.EntryID)
	}
	if result.ReportSHA256 == "" {
		t.Error("expected non-empty ReportSHA256")
	}
}

func TestSubmitServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	s := NewReceiptSubmitter(srv.URL)
	ctx := context.Background()

	_, err := s.Submit(ctx, Receipt{
		JobID:     "job-123",
		ArgsHash:  "abc123",
		Signature: "sig",
		KeyID:     "k1",
	})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !contains(err.Error(), "unexpected status 500") {
		t.Errorf("expected status 500 in error, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
