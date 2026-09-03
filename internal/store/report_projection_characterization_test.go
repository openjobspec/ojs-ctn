package store

import (
	"context"
	"encoding/json"
	"testing"
)

func TestReportProjectionFallbacksCharacterization(t *testing.T) {
	tests := []struct {
		name       string
		report     string
		backend    string
		runAt      string
		level      int
		conformant bool
	}{
		{
			name:       "all fields",
			report:     `{"backend":{"name":"postgres"},"target":"fallback","run_at":"2026-04-18T12:00:00Z","conformant_level":4,"conformant":true}`,
			backend:    "postgres",
			runAt:      "2026-04-18T12:00:00Z",
			level:      4,
			conformant: true,
		},
		{
			name:    "empty backend falls back to target",
			report:  `{"backend":{"name":""},"target":"redis","conformant_level":0}`,
			backend: "redis",
			level:   0,
		},
		{
			name:   "missing fields",
			report: `{}`,
			level:  0,
		},
		{
			name:   "invalid json",
			report: `invalid`,
			level:  -1,
		},
		{
			name:   "wrong field types",
			report: `{"backend":"postgres","run_at":7,"conformant_level":"4","conformant":"true"}`,
			level:  -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := json.RawMessage(tt.report)
			if got := ExtractBackendName(report); got != tt.backend {
				t.Fatalf("backend = %q, want %q", got, tt.backend)
			}
			if got := ExtractRunAt(report); got != tt.runAt {
				t.Fatalf("run_at = %q, want %q", got, tt.runAt)
			}
			if got := ExtractConformantLevel(report); got != tt.level {
				t.Fatalf("level = %d, want %d", got, tt.level)
			}
			if got := ExtractConformant(report); got != tt.conformant {
				t.Fatalf("conformant = %t, want %t", got, tt.conformant)
			}
		})
	}
}

func TestRegistryProjectionOrderAndMalformedReports(t *testing.T) {
	s := openTempStore(t)
	defer s.Close()
	appendReport := func(report string) {
		t.Helper()
		if _, err := s.Append(context.Background(), Submission{
			Report:             json.RawMessage(report),
			SubmitterSignature: "signature",
			SubmitterKeyID:     "key",
		}); err != nil {
			t.Fatal(err)
		}
	}
	appendReport(`"invalid"`)
	appendReport(`{"target":"redis","run_at":"first","conformant_level":2,"conformant":false}`)
	appendReport(`{"backend":{"name":"redis"},"run_at":"latest","conformant_level":4,"conformant":true}`)

	backends := s.ListBackends()
	if len(backends) != 2 {
		t.Fatalf("backends = %+v", backends)
	}
	if backends[0].BackendName != "redis" || backends[0].TotalRuns != 2 ||
		backends[0].LatestRunAt != "latest" || backends[0].LatestLevel != 4 ||
		!backends[0].LatestConformant {
		t.Fatalf("redis summary = %+v", backends[0])
	}
	if backends[1].BackendName != "unknown" || backends[1].TotalRuns != 1 ||
		backends[1].LatestLevel != -1 || backends[1].LatestConformant {
		t.Fatalf("unknown summary = %+v", backends[1])
	}

	redisEntries := s.EntriesForBackend("redis")
	if len(redisEntries) != 2 || redisEntries[0].SequenceNumber != 3 || redisEntries[1].SequenceNumber != 2 {
		t.Fatalf("redis entries = %+v", redisEntries)
	}
	unknownEntries := s.EntriesForBackend("unknown")
	if len(unknownEntries) != 1 || unknownEntries[0].SequenceNumber != 1 {
		t.Fatalf("unknown entries = %+v", unknownEntries)
	}
}
