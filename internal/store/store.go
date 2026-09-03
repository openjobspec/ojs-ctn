// Package store implements the P1 append-only ledger for the Conformance
// Trust Network. It uses a single JSON-lines file as the source of truth:
// each line is a fully-formed Entry. This keeps P1 dependency-free and
// makes the store trivially auditable with `cat`, `jq`, and `wc -l`.
//
// P2+ will introduce a Merkle log + Postgres-backed indexing on top of
// this same file format.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Submission is what a partner POSTs.
type Submission struct {
	Report             json.RawMessage `json:"report"`
	SubmitterSignature string          `json:"submitter_signature"`
	SubmitterKeyID     string          `json:"submitter_key_id"`
}

// Entry is what the ledger stores and serves.
type Entry struct {
	EntryID             string               `json:"entry_id"`
	LoggedAt            time.Time            `json:"logged_at"`
	ReportSHA256        string               `json:"report_sha256"`
	Report              json.RawMessage      `json:"report"`
	SubmitterSignature  string               `json:"submitter_signature"`
	SubmitterKeyID      string               `json:"submitter_key_id"`
	SequenceNumber      uint64               `json:"sequence_number"`
	WitnessCosignatures []WitnessCosignature `json:"witness_cosignatures,omitempty"`
}

// WitnessCosignature is a third-party endorsement of an entry. Multiple
// cosignatures from different witnesses can attach to the same entry.
type WitnessCosignature struct {
	WitnessKeyID     string    `json:"witness_key_id"`
	WitnessSignature string    `json:"witness_signature"`
	CosignedAt       time.Time `json:"cosigned_at"`
}

// Head describes the current state of the ledger.
type Head struct {
	SequenceNumber uint64    `json:"sequence_number"`
	LastEntryID    string    `json:"last_entry_id"`
	LastEntrySHA   string    `json:"last_entry_sha256"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Store is the single-writer, multi-reader append-only ledger.
type Store struct {
	mu    sync.RWMutex
	log   *appendLog
	index *ledgerIndex
}

// Open creates or opens the ledger file at path. The file is created with
// 0600 perms. Concurrent processes opening the same path produce
// undefined behavior — single-writer is enforced by convention, not flock.
func Open(path string) (*Store, error) {
	records, err := replayLedger(path)
	if err != nil {
		return nil, err
	}
	log, err := openAppendLog(path)
	if err != nil {
		return nil, err
	}
	return newStore(log, newLedgerIndex(records)), nil
}

func newStore(log *appendLog, index *ledgerIndex) *Store {
	return &Store{log: log, index: index}
}

// Close flushes and closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log.Close()
}

// Append writes a new entry. Returns the populated Entry on success.
func (s *Store) Append(_ context.Context, sub Submission) (*Entry, error) {
	if len(sub.Report) == 0 {
		return nil, errors.New("submission.report is empty")
	}
	if sub.SubmitterKeyID == "" {
		return nil, errors.New("submission.submitter_key_id is empty")
	}
	if sub.SubmitterSignature == "" {
		return nil, errors.New("submission.submitter_signature is empty")
	}

	digest := sha256.Sum256(sub.Report)
	entryID := newEntryID()

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := Entry{
		EntryID:            entryID,
		LoggedAt:           time.Now().UTC(),
		ReportSHA256:       hex.EncodeToString(digest[:]),
		Report:             sub.Report,
		SubmitterSignature: sub.SubmitterSignature,
		SubmitterKeyID:     sub.SubmitterKeyID,
		SequenceNumber:     uint64(s.index.count()) + 1,
	}

	line, lineHash, err := encodeEntry(entry)
	if err != nil {
		return nil, err
	}
	if err := s.log.Append(line); err != nil {
		return nil, err
	}

	s.index.appendEntry(entry, lineHash)

	return &entry, nil
}

// Get returns the entry by ID.
func (s *Store) Get(_ context.Context, entryID string) (*Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.index.get(entryID)
	if !ok {
		return nil, fmt.Errorf("entry %q not found", entryID)
	}
	return &e, nil
}

// Cosign appends a witness cosignature to an existing entry. The
// signature itself is opaque to the ledger — verification happens at
// the API layer (and again client-side by ctn-verify). Idempotent on
// (entry_id, witness_key_id): re-cosigning by the same witness
// replaces the prior cosignature in memory but appends a new line on
// disk, preserving full audit history.
func (s *Store) Cosign(_ context.Context, entryID, witnessKeyID, witnessSig string) (*Entry, error) {
	if entryID == "" {
		return nil, errors.New("cosign: entry_id required")
	}
	if witnessKeyID == "" {
		return nil, errors.New("cosign: witness_key_id required")
	}
	if witnessSig == "" {
		return nil, errors.New("cosign: witness_signature required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.index.has(entryID) {
		return nil, fmt.Errorf("cosign: entry %q not found", entryID)
	}

	now := time.Now().UTC()
	cosig := WitnessCosignature{
		WitnessKeyID:     witnessKeyID,
		WitnessSignature: witnessSig,
		CosignedAt:       now,
	}

	line, err := encodeCosignature(entryID, cosig)
	if err != nil {
		return nil, err
	}
	if err := s.log.Append(line); err != nil {
		return nil, err
	}

	e := s.index.cosign(entryID, cosig)
	return &e, nil
}

// Head returns the current ledger head.
func (s *Store) Head(_ context.Context) Head {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.head(time.Now().UTC())
}

// Count returns the number of entries (for diagnostics).
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.count()
}

// newEntryID returns a uuidv7-ish identifier. P1 uses a simple
// timestamp-prefixed random tail; P2 will switch to RFC 9562 uuidv7.
func newEntryID() string {
	now := time.Now().UTC().UnixMilli()
	rnd := make([]byte, 8)
	// Reuse the package's existing rand source via crypto/rand for unguessability.
	if _, err := readRand(rnd); err != nil {
		// rand cannot fail on Linux/macOS in practice; if it does, fall back to
		// timestamp-only — duplicate IDs will cause Append to silently overwrite
		// an existing byID entry, which is logged as a fatal error in tests.
		return fmt.Sprintf("%016x", now)
	}
	return fmt.Sprintf("%013x-%s", now, hex.EncodeToString(rnd))
}
