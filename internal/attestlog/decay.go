// Package attestlog — decay and revocation support for CTN attestations.
//
// An attestation entry transitions through three lifecycle states:
//
//   - Active:   freshly logged and within the configured MaxAge window.
//   - Outdated: still valid but older than MaxAge — consumers SHOULD
//     re-attest.
//   - Revoked:  explicitly invalidated via the revocation log — the
//     entry MUST NOT be trusted.
//
// RevocationLog is an in-memory, thread-safe registry of revoked entry
// IDs. It is designed for P1 scale (single node); P2 will persist
// revocations to the ledger file alongside cosignature lines.

package attestlog

import (
	"errors"
	"sync"
	"time"

	"github.com/openjobspec/ojs-ctn/internal/store"
)

// AttestationStatus represents the lifecycle state of an attestation entry.
type AttestationStatus string

const (
	Active   AttestationStatus = "active"
	Outdated AttestationStatus = "outdated"
	Revoked  AttestationStatus = "revoked"
)

// DefaultMaxAge is the default attestation freshness window (90 days).
const DefaultMaxAge = 90 * 24 * time.Hour

// DecayConfig controls how attestation age is evaluated.
type DecayConfig struct {
	MaxAge time.Duration
}

// DefaultDecayConfig returns a DecayConfig with the default 90-day window.
func DefaultDecayConfig() DecayConfig {
	return DecayConfig{MaxAge: DefaultMaxAge}
}

// StatusResult is the JSON-serializable status of an entry.
type StatusResult struct {
	EntryID string            `json:"entry_id"`
	Status  AttestationStatus `json:"status"`
	Reason  string            `json:"reason,omitempty"`
	Age     string            `json:"age"`
}

// StatusChecker evaluates the lifecycle status of attestation entries.
type StatusChecker struct {
	Config      DecayConfig
	Revocations *RevocationLog
}

// Check determines the status of the given store.Entry.
func (sc *StatusChecker) Check(entry *store.Entry) StatusResult {
	if sc.Revocations != nil {
		if revoked, reason := sc.Revocations.IsRevoked(entry.EntryID); revoked {
			return StatusResult{
				EntryID: entry.EntryID,
				Status:  Revoked,
				Reason:  reason,
				Age:     time.Since(entry.LoggedAt).Truncate(time.Second).String(),
			}
		}
	}

	maxAge := sc.Config.MaxAge
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}

	age := time.Since(entry.LoggedAt)
	status := Active
	if age > maxAge {
		status = Outdated
	}

	return StatusResult{
		EntryID: entry.EntryID,
		Status:  status,
		Age:     age.Truncate(time.Second).String(),
	}
}

// RevocationEntry records a single revocation event.
type RevocationEntry struct {
	EntryID   string    `json:"entry_id"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevocationLog is a thread-safe in-memory map of entry_id → revocation.
type RevocationLog struct {
	mu      sync.RWMutex
	entries map[string]RevocationEntry
}

// NewRevocationLog creates an empty revocation log.
func NewRevocationLog() *RevocationLog {
	return &RevocationLog{
		entries: make(map[string]RevocationEntry),
	}
}

// Revoke marks an entry as revoked. Idempotent: re-revoking the same
// entry updates the reason and timestamp.
func (rl *RevocationLog) Revoke(entryID, reason string) error {
	if entryID == "" {
		return errors.New("attestlog: entry_id required for revocation")
	}
	if reason == "" {
		return errors.New("attestlog: reason required for revocation")
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.entries[entryID] = RevocationEntry{
		EntryID:   entryID,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
	}
	return nil
}

// IsRevoked returns whether the entry has been revoked and the reason.
func (rl *RevocationLog) IsRevoked(entryID string) (bool, string) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	entry, ok := rl.entries[entryID]
	if !ok {
		return false, ""
	}
	return true, entry.Reason
}

// List returns all revocation entries. The returned slice is a snapshot;
// callers may modify it freely.
func (rl *RevocationLog) List() []RevocationEntry {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	result := make([]RevocationEntry, 0, len(rl.entries))
	for _, e := range rl.entries {
		result = append(result, e)
	}
	return result
}
