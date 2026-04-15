// Package store implements the P1 append-only ledger for the Conformance
// Trust Network. It uses a single JSON-lines file as the source of truth:
// each line is a fully-formed Entry. This keeps P1 dependency-free and
// makes the store trivially auditable with `cat`, `jq`, and `wc -l`.
//
// P2+ will introduce a Merkle log + Postgres-backed indexing on top of
// this same file format.
package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	EntryID            string                `json:"entry_id"`
	LoggedAt           time.Time             `json:"logged_at"`
	ReportSHA256       string                `json:"report_sha256"`
	Report             json.RawMessage       `json:"report"`
	SubmitterSignature string                `json:"submitter_signature"`
	SubmitterKeyID     string                `json:"submitter_key_id"`
	SequenceNumber     uint64                `json:"sequence_number"`
	WitnessCosignatures []WitnessCosignature `json:"witness_cosignatures,omitempty"`
}

// WitnessCosignature is a third-party endorsement of an entry. Multiple
// cosignatures from different witnesses can attach to the same entry.
type WitnessCosignature struct {
	WitnessKeyID     string    `json:"witness_key_id"`
	WitnessSignature string    `json:"witness_signature"`
	CosignedAt       time.Time `json:"cosigned_at"`
}

// cosigLine is the wire shape of a cosignature record on disk. We tag
// it with an outer `cosig` envelope so replay can distinguish entries
// from cosigs without ambiguity. Existing entry lines are unaffected
// because they never have a top-level `cosig` field.
type cosigLine struct {
	Cosig struct {
		EntryID          string    `json:"entry_id"`
		WitnessKeyID     string    `json:"witness_key_id"`
		WitnessSignature string    `json:"witness_signature"`
		CosignedAt       time.Time `json:"cosigned_at"`
	} `json:"cosig"`
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
	mu       sync.RWMutex
	path     string
	f        *os.File
	w        *bufio.Writer
	entries  []Entry          // in-memory mirror; small enough for P1 scale
	byID     map[string]int   // entry_id -> index in entries
	headHash string           // sha256 of last entry's JSON line
}

// Open creates or opens the ledger file at path. The file is created with
// 0600 perms. Concurrent processes opening the same path produce
// undefined behavior — single-writer is enforced by convention, not flock.
func Open(path string) (*Store, error) {
	// Replay existing entries first.
	entries, head, err := replay(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	s := &Store{
		path:     path,
		f:        f,
		w:        bufio.NewWriter(f),
		entries:  entries,
		byID:     make(map[string]int, len(entries)),
		headHash: head,
	}
	for i, e := range entries {
		s.byID[e.EntryID] = i
	}
	return s, nil
}

// Close flushes and closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w != nil {
		_ = s.w.Flush()
	}
	return s.f.Close()
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
		SequenceNumber:     uint64(len(s.entries)) + 1,
	}

	line, err := json.Marshal(&entry)
	if err != nil {
		return nil, err
	}
	if _, err := s.w.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	if err := s.w.Flush(); err != nil {
		return nil, err
	}
	if err := s.f.Sync(); err != nil {
		return nil, err
	}

	s.entries = append(s.entries, entry)
	s.byID[entry.EntryID] = len(s.entries) - 1
	lineHash := sha256.Sum256(line)
	s.headHash = hex.EncodeToString(lineHash[:])

	return &entry, nil
}

// Get returns the entry by ID.
func (s *Store) Get(_ context.Context, entryID string) (*Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.byID[entryID]
	if !ok {
		return nil, fmt.Errorf("entry %q not found", entryID)
	}
	e := s.entries[idx]
	// Defensive copy of cosigs slice so callers can't mutate ours.
	if len(e.WitnessCosignatures) > 0 {
		cs := make([]WitnessCosignature, len(e.WitnessCosignatures))
		copy(cs, e.WitnessCosignatures)
		e.WitnessCosignatures = cs
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

	idx, ok := s.byID[entryID]
	if !ok {
		return nil, fmt.Errorf("cosign: entry %q not found", entryID)
	}

	now := time.Now().UTC()
	cosig := WitnessCosignature{
		WitnessKeyID:     witnessKeyID,
		WitnessSignature: witnessSig,
		CosignedAt:       now,
	}

	var line cosigLine
	line.Cosig.EntryID = entryID
	line.Cosig.WitnessKeyID = witnessKeyID
	line.Cosig.WitnessSignature = witnessSig
	line.Cosig.CosignedAt = now

	bytes, err := json.Marshal(line)
	if err != nil {
		return nil, err
	}
	if _, err := s.w.Write(append(bytes, '\n')); err != nil {
		return nil, err
	}
	if err := s.w.Flush(); err != nil {
		return nil, err
	}
	if err := s.f.Sync(); err != nil {
		return nil, err
	}

	// Replace prior cosig from same witness if any.
	replaced := false
	for i, c := range s.entries[idx].WitnessCosignatures {
		if c.WitnessKeyID == witnessKeyID {
			s.entries[idx].WitnessCosignatures[i] = cosig
			replaced = true
			break
		}
	}
	if !replaced {
		s.entries[idx].WitnessCosignatures = append(s.entries[idx].WitnessCosignatures, cosig)
	}

	e := s.entries[idx]
	cs := make([]WitnessCosignature, len(e.WitnessCosignatures))
	copy(cs, e.WitnessCosignatures)
	e.WitnessCosignatures = cs
	return &e, nil
}

// Head returns the current ledger head.
func (s *Store) Head(_ context.Context) Head {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := Head{
		SequenceNumber: uint64(len(s.entries)),
		UpdatedAt:      time.Now().UTC(),
		LastEntrySHA:   s.headHash,
	}
	if len(s.entries) > 0 {
		h.LastEntryID = s.entries[len(s.entries)-1].EntryID
	}
	return h
}

// Count returns the number of entries (for diagnostics).
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func replay(path string) ([]Entry, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var entries []Entry
	byID := map[string]int{}
	var lastHash string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Discriminate: cosignature lines have a top-level "cosig" object.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, "", fmt.Errorf("corrupt ledger line %d: %w", lineNum, err)
		}
		if _, isCosig := probe["cosig"]; isCosig {
			var c cosigLine
			if err := json.Unmarshal(line, &c); err != nil {
				return nil, "", fmt.Errorf("corrupt cosig line %d: %w", lineNum, err)
			}
			idx, ok := byID[c.Cosig.EntryID]
			if !ok {
				// Orphan cosig — log skipped; unlikely outside corruption.
				continue
			}
			cosig := WitnessCosignature{
				WitnessKeyID:     c.Cosig.WitnessKeyID,
				WitnessSignature: c.Cosig.WitnessSignature,
				CosignedAt:       c.Cosig.CosignedAt,
			}
			replaced := false
			for i, prior := range entries[idx].WitnessCosignatures {
				if prior.WitnessKeyID == cosig.WitnessKeyID {
					entries[idx].WitnessCosignatures[i] = cosig
					replaced = true
					break
				}
			}
			if !replaced {
				entries[idx].WitnessCosignatures = append(entries[idx].WitnessCosignatures, cosig)
			}
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, "", fmt.Errorf("corrupt ledger line %d: %w", lineNum, err)
		}
		entries = append(entries, e)
		byID[e.EntryID] = len(entries) - 1
		h := sha256.Sum256(append([]byte{}, line...))
		lastHash = hex.EncodeToString(h[:])
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, "", err
	}
	return entries, lastHash, nil
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
