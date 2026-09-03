package attestlog

import (
	"testing"
	"time"

	"github.com/openjobspec/ojs-ctn/internal/store"
)

func TestFreshnessThresholdsCharacterization(t *testing.T) {
	now := time.Date(2026, 8, 3, 1, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		config DecayConfig
		logged time.Time
		status AttestationStatus
		age    string
	}{
		{
			name: "below threshold", config: DecayConfig{MaxAge: time.Hour},
			logged: now.Add(-time.Hour + time.Nanosecond), status: Active, age: "59m59s",
		},
		{
			name: "exact threshold", config: DecayConfig{MaxAge: time.Hour},
			logged: now.Add(-time.Hour), status: Active, age: "1h0m0s",
		},
		{
			name: "above threshold", config: DecayConfig{MaxAge: time.Hour},
			logged: now.Add(-time.Hour - time.Nanosecond), status: Outdated, age: "1h0m0s",
		},
		{
			name: "zero uses default at boundary", config: DecayConfig{},
			logged: now.Add(-DefaultMaxAge), status: Active, age: "2160h0m0s",
		},
		{
			name: "zero uses default above boundary", config: DecayConfig{},
			logged: now.Add(-DefaultMaxAge - time.Nanosecond), status: Outdated, age: "2160h0m0s",
		},
		{
			name: "negative maximum", config: DecayConfig{MaxAge: -time.Second},
			logged: now, status: Outdated, age: "0s",
		},
		{
			name: "future entry", config: DecayConfig{MaxAge: time.Hour},
			logged: now.Add(time.Second), status: Active, age: "-1s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := StatusChecker{Config: tt.config}
			result := checker.checkAt(&store.Entry{EntryID: "entry-1", LoggedAt: tt.logged}, now)
			if result != (StatusResult{EntryID: "entry-1", Status: tt.status, Age: tt.age}) {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestRevocationPrecedesFreshnessCharacterization(t *testing.T) {
	now := time.Date(2026, 8, 3, 1, 0, 0, 0, time.UTC)
	revocations := NewRevocationLog()
	if err := revocations.Revoke("entry-1", "compromised"); err != nil {
		t.Fatal(err)
	}
	checker := StatusChecker{
		Config:      DecayConfig{MaxAge: time.Hour},
		Revocations: revocations,
	}
	result := checker.checkAt(&store.Entry{
		EntryID:  "entry-1",
		LoggedAt: now.Add(-2 * time.Hour),
	}, now)
	want := StatusResult{
		EntryID: "entry-1",
		Status:  Revoked,
		Reason:  "compromised",
		Age:     "2h0m0s",
	}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
}

func TestRevocationListIsDefensiveSnapshot(t *testing.T) {
	log := NewRevocationLog()
	if err := log.Revoke("entry-1", "reason"); err != nil {
		t.Fatal(err)
	}
	list := log.List()
	list[0].Reason = "mutated"

	revoked, reason := log.IsRevoked("entry-1")
	if !revoked || reason != "reason" {
		t.Fatalf("revocation after caller mutation = %t, %q", revoked, reason)
	}
}

func TestRevocationValidationErrorsGolden(t *testing.T) {
	log := NewRevocationLog()
	if err := log.Revoke("", "reason"); err == nil ||
		err.Error() != "attestlog: entry_id required for revocation" {
		t.Fatalf("empty entry error = %v", err)
	}
	if err := log.Revoke("entry-1", ""); err == nil ||
		err.Error() != "attestlog: reason required for revocation" {
		t.Fatalf("empty reason error = %v", err)
	}
}
