package attestlog

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openjobspec/ojs-ctn/internal/store"
)

func makeEntry(id string, age time.Duration) *store.Entry {
	return &store.Entry{
		EntryID:  id,
		LoggedAt: time.Now().Add(-age),
		Report:   json.RawMessage(`{"test":true}`),
	}
}

func TestDecayActive(t *testing.T) {
	sc := StatusChecker{
		Config:      DefaultDecayConfig(),
		Revocations: NewRevocationLog(),
	}
	entry := makeEntry("e-active", 1*time.Hour)
	result := sc.Check(entry)
	if result.Status != Active {
		t.Errorf("expected status %q, got %q", Active, result.Status)
	}
	if result.EntryID != "e-active" {
		t.Errorf("expected entry_id %q, got %q", "e-active", result.EntryID)
	}
}

func TestDecayOutdated(t *testing.T) {
	sc := StatusChecker{
		Config:      DecayConfig{MaxAge: 1 * time.Hour},
		Revocations: NewRevocationLog(),
	}
	entry := makeEntry("e-old", 2*time.Hour)
	result := sc.Check(entry)
	if result.Status != Outdated {
		t.Errorf("expected status %q, got %q", Outdated, result.Status)
	}
}

func TestRevoke(t *testing.T) {
	rl := NewRevocationLog()
	if err := rl.Revoke("e1", "compromised key"); err != nil {
		t.Fatal(err)
	}
	revoked, reason := rl.IsRevoked("e1")
	if !revoked {
		t.Fatal("expected e1 to be revoked")
	}
	if reason != "compromised key" {
		t.Errorf("expected reason %q, got %q", "compromised key", reason)
	}

	// StatusChecker should return Revoked for this entry.
	sc := StatusChecker{
		Config:      DefaultDecayConfig(),
		Revocations: rl,
	}
	entry := makeEntry("e1", 1*time.Minute)
	result := sc.Check(entry)
	if result.Status != Revoked {
		t.Errorf("expected status %q, got %q", Revoked, result.Status)
	}
	if result.Reason != "compromised key" {
		t.Errorf("expected reason %q, got %q", "compromised key", result.Reason)
	}
}

func TestRevokeIdempotent(t *testing.T) {
	rl := NewRevocationLog()
	if err := rl.Revoke("e1", "reason-1"); err != nil {
		t.Fatal(err)
	}
	if err := rl.Revoke("e1", "reason-2"); err != nil {
		t.Fatal(err)
	}
	_, reason := rl.IsRevoked("e1")
	if reason != "reason-2" {
		t.Errorf("expected updated reason %q, got %q", "reason-2", reason)
	}
	entries := rl.List()
	count := 0
	for _, e := range entries {
		if e.EntryID == "e1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 entry for e1, got %d", count)
	}
}

func TestIsRevokedNotFound(t *testing.T) {
	rl := NewRevocationLog()
	revoked, reason := rl.IsRevoked("nonexistent")
	if revoked {
		t.Error("expected nonexistent entry not to be revoked")
	}
	if reason != "" {
		t.Errorf("expected empty reason, got %q", reason)
	}
}

func TestRevocationList(t *testing.T) {
	rl := NewRevocationLog()
	rl.Revoke("a", "reason-a")
	rl.Revoke("b", "reason-b")
	rl.Revoke("c", "reason-c")

	entries := rl.List()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	found := map[string]bool{}
	for _, e := range entries {
		found[e.EntryID] = true
		if e.RevokedAt.IsZero() {
			t.Errorf("entry %q has zero revoked_at", e.EntryID)
		}
	}
	for _, id := range []string{"a", "b", "c"} {
		if !found[id] {
			t.Errorf("missing entry %q in list", id)
		}
	}
}

func TestRevokeValidation(t *testing.T) {
	rl := NewRevocationLog()
	if err := rl.Revoke("", "reason"); err == nil {
		t.Error("expected error for empty entry_id")
	}
	if err := rl.Revoke("e1", ""); err == nil {
		t.Error("expected error for empty reason")
	}
}
