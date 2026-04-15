// Package dag is the M2/P0 spike implementation of the agent-state Merkle
// DAG primitive that backs ASP (Agent Substrate Protocol). It demonstrates
// that the data model from MOONSHOT_BRIEF M2 is buildable: content-
// addressed nodes form an append-only DAG; any branch can be Forked into a
// new tip; two tips can be Merged with explicit conflict surfacing.
//
// Scope (P0): in-memory, single-process, no persistence. Persistence and
// network gossip land in M2/P1. The wire types here are deliberately
// minimal — a Node is just (parents, payload, contentID).
package dag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Node is a content-addressed Merkle DAG node. ContentID is derived
// deterministically from (sorted parent IDs + canonical-JSON payload) so
// that two stores with the same payload arrive at the same ID without
// coordinating.
type Node struct {
	ContentID string          `json:"content_id"`
	Parents   []string        `json:"parents"`
	Payload   json.RawMessage `json:"payload"`
}

// Store is the in-memory DAG with a tip per branch name.
type Store struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	tips  map[string]string // branch -> tip content id
}

// New returns an empty DAG.
func New() *Store {
	return &Store{
		nodes: make(map[string]*Node),
		tips:  make(map[string]string),
	}
}

// computeID derives the content ID for a (parents, payload) pair.
// Parents are sorted before hashing to make the ID independent of insertion
// order; this is what lets two replicas converge to the same ID.
func computeID(parents []string, payload []byte) string {
	sorted := append([]string(nil), parents...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, p := range sorted {
		h.Write([]byte(p))
		h.Write([]byte{0x1F})
	}
	h.Write([]byte{0x1E})
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// Append adds a new node on the named branch with the given payload. The
// branch's current tip becomes the sole parent. If the branch doesn't
// exist, the new node has no parents (it's a root).
func (s *Store) Append(branch string, payload any) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("dag: marshal payload: %w", err)
	}
	var parents []string
	if tip, ok := s.tips[branch]; ok {
		parents = []string{tip}
	}
	id := computeID(parents, raw)
	if existing, ok := s.nodes[id]; ok {
		// Idempotent insert: same content => same id.
		s.tips[branch] = id
		return existing, nil
	}
	n := &Node{ContentID: id, Parents: parents, Payload: raw}
	s.nodes[id] = n
	s.tips[branch] = id
	return n, nil
}

// Fork creates a new branch starting at the tip of an existing branch.
// Returns an error if the source branch doesn't exist or the destination
// branch already exists.
func (s *Store) Fork(src, dst string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tip, ok := s.tips[src]
	if !ok {
		return fmt.Errorf("dag: source branch %q does not exist", src)
	}
	if _, exists := s.tips[dst]; exists {
		return fmt.Errorf("dag: destination branch %q already exists", dst)
	}
	s.tips[dst] = tip
	return nil
}

// Merge creates a new node on dst whose parents are the tips of dst and
// src. mergeFn is called with the two parent payloads and returns the
// merged payload. If mergeFn returns ErrConflict the merge is aborted.
//
// This is the 3-way merge primitive ASP needs to reconcile two divergent
// agent-state branches deterministically.
type MergeFn func(dst, src json.RawMessage) (any, error)

// ErrConflict is the sentinel mergeFn returns when the two payloads cannot
// be reconciled and human/agent intervention is required.
var ErrConflict = errors.New("dag: merge conflict")

// Merge applies mergeFn to (dst-tip, src-tip) and appends the result on dst.
func (s *Store) Merge(dst, src string, mergeFn MergeFn) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dstTip, ok := s.tips[dst]
	if !ok {
		return nil, fmt.Errorf("dag: dst branch %q does not exist", dst)
	}
	srcTip, ok := s.tips[src]
	if !ok {
		return nil, fmt.Errorf("dag: src branch %q does not exist", src)
	}
	if dstTip == srcTip {
		// Already converged; nothing to do.
		return s.nodes[dstTip], nil
	}
	dstNode := s.nodes[dstTip]
	srcNode := s.nodes[srcTip]
	merged, err := mergeFn(dstNode.Payload, srcNode.Payload)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	parents := []string{dstTip, srcTip}
	id := computeID(parents, raw)
	if existing, ok := s.nodes[id]; ok {
		s.tips[dst] = id
		return existing, nil
	}
	n := &Node{ContentID: id, Parents: parents, Payload: raw}
	s.nodes[id] = n
	s.tips[dst] = id
	return n, nil
}

// Tip returns the current head node of a branch.
func (s *Store) Tip(branch string) (*Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.tips[branch]
	if !ok {
		return nil, false
	}
	return s.nodes[id], true
}

// Get returns a node by content id.
func (s *Store) Get(id string) (*Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	return n, ok
}

// Len returns the number of distinct nodes (deduplicated by content id).
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}
