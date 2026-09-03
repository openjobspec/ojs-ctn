package main

import (
	"context"
	"fmt"
	"sync"
)

// Mirror is the orchestration layer.
type Mirror struct {
	CTN       CTNClient
	Rekor     RekorClient
	State     State
	StatePath string

	mu         sync.Mutex
	stateStore statePersistence
}

// Tick performs one poll-and-mirror pass. Returns the number of newly
// mirrored entries.
//
// The algorithm intentionally mirrors only the head entry per tick when
// there's a gap > 1, then catches up on subsequent ticks. This keeps
// the daemon's per-tick latency bounded and gives the operator time to
// notice if Rekor starts rejecting submissions before we exhaust our
// rate budget.
func (m *Mirror) Tick(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	head, err := m.CTN.Head(ctx)
	if err != nil {
		return 0, fmt.Errorf("head: %w", err)
	}
	if head.SequenceNumber <= m.State.LastMirroredSeq {
		return 0, nil
	}
	if head.LastEntryID == "" {
		return 0, nil
	}
	if _, alreadyMirrored := m.State.UUIDs[head.LastEntryID]; alreadyMirrored {
		m.State.LastMirroredSeq = head.SequenceNumber
		return 0, m.persistState()
	}
	entry, err := m.CTN.EntryByID(ctx, head.LastEntryID)
	if err != nil {
		return 0, fmt.Errorf("entry %s: %w", head.LastEntryID, err)
	}
	uuid, err := m.Rekor.Submit(ctx, entry)
	if err != nil {
		return 0, fmt.Errorf("rekor submit %s: %w", head.LastEntryID, err)
	}
	m.State.UUIDs[head.LastEntryID] = uuid
	m.State.LastMirroredSeq = head.SequenceNumber
	if err := m.persistState(); err != nil {
		return 0, fmt.Errorf("save state: %w", err)
	}
	return 1, nil
}

func (m *Mirror) persistState() error {
	if m.stateStore != nil {
		return m.stateStore.Save(m.State)
	}
	return saveState(m.StatePath, m.State)
}
