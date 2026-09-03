package attestlog

import (
	"errors"
	"sync"
	"time"
)

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
	for _, entry := range rl.entries {
		result = append(result, entry)
	}
	return result
}
