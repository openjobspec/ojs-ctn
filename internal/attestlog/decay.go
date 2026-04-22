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
	revoked, reason := sc.revocation(entry.EntryID)
	if revoked {
		return revokedStatusAt(entry, time.Now(), reason)
	}
	policy := newFreshnessPolicy(sc.Config)
	return freshnessStatusAt(entry, time.Now(), policy)
}
