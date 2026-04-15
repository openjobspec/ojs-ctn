package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// stub clients

type stubCTN struct {
	mu      sync.Mutex
	heads   []CTNHead // pop from front each Head() call
	entries map[string]json.RawMessage
}

func (s *stubCTN) Head(_ context.Context) (CTNHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.heads) == 0 {
		return CTNHead{}, errors.New("no head")
	}
	h := s.heads[0]
	if len(s.heads) > 1 {
		s.heads = s.heads[1:]
	}
	return h, nil
}
func (s *stubCTN) EntryByID(_ context.Context, id string) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return e, nil
}
func (s *stubCTN) HeadIDs(_ context.Context) ([]string, error) { return nil, nil }

type stubRekor struct {
	mu       sync.Mutex
	received []json.RawMessage
	nextUUID int
	failOnce bool
}

func (s *stubRekor) Submit(_ context.Context, e json.RawMessage) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failOnce {
		s.failOnce = false
		return "", errors.New("transient")
	}
	s.nextUUID++
	s.received = append(s.received, e)
	return "rekor-uuid-" + itoa(s.nextUUID), nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	bp := len(buf)
	for i > 0 {
		bp--
		buf[bp] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[bp:])
}

func TestMirrorTickHappyPath(t *testing.T) {
	dir := t.TempDir()
	ctn := &stubCTN{
		heads: []CTNHead{
			{SequenceNumber: 5, LastEntryID: "e5"},
		},
		entries: map[string]json.RawMessage{
			"e5": json.RawMessage(`{"entry_id":"e5","report_sha256":"abc"}`),
		},
	}
	rekor := &stubRekor{}
	m := &Mirror{
		CTN:       ctn,
		Rekor:     rekor,
		State:     State{UUIDs: map[string]string{}},
		StatePath: filepath.Join(dir, "state.json"),
	}
	n, err := m.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 mirrored, got %d", n)
	}
	if len(rekor.received) != 1 {
		t.Fatalf("rekor got %d submissions", len(rekor.received))
	}
	if m.State.LastMirroredSeq != 5 {
		t.Errorf("LastMirroredSeq = %d, want 5", m.State.LastMirroredSeq)
	}
	if m.State.UUIDs["e5"] != "rekor-uuid-1" {
		t.Errorf("uuid map: %v", m.State.UUIDs)
	}
}

func TestMirrorTickIdempotent(t *testing.T) {
	dir := t.TempDir()
	ctn := &stubCTN{
		heads:   []CTNHead{{SequenceNumber: 5, LastEntryID: "e5"}, {SequenceNumber: 5, LastEntryID: "e5"}},
		entries: map[string]json.RawMessage{"e5": json.RawMessage(`{}`)},
	}
	rekor := &stubRekor{}
	m := &Mirror{CTN: ctn, Rekor: rekor, State: State{UUIDs: map[string]string{}}, StatePath: filepath.Join(dir, "s.json")}
	if _, err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	n, err := m.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("second tick on same head should mirror 0, got %d", n)
	}
	if len(rekor.received) != 1 {
		t.Errorf("rekor should not be called twice, got %d submissions", len(rekor.received))
	}
}

func TestMirrorAlreadySubmittedSkipsRekor(t *testing.T) {
	dir := t.TempDir()
	ctn := &stubCTN{
		heads:   []CTNHead{{SequenceNumber: 7, LastEntryID: "e7"}},
		entries: map[string]json.RawMessage{"e7": json.RawMessage(`{}`)},
	}
	rekor := &stubRekor{}
	state := State{LastMirroredSeq: 6, UUIDs: map[string]string{"e7": "pre-existing-uuid"}}
	m := &Mirror{CTN: ctn, Rekor: rekor, State: state, StatePath: filepath.Join(dir, "s.json")}
	n, err := m.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 (already mirrored), got %d", n)
	}
	if len(rekor.received) != 0 {
		t.Errorf("Rekor should not be re-submitted, got %d", len(rekor.received))
	}
	if m.State.LastMirroredSeq != 7 {
		t.Errorf("seq counter should still bump to 7, got %d", m.State.LastMirroredSeq)
	}
}

func TestMirrorRekorFailureLeavesStateIntact(t *testing.T) {
	dir := t.TempDir()
	ctn := &stubCTN{
		heads:   []CTNHead{{SequenceNumber: 1, LastEntryID: "e1"}},
		entries: map[string]json.RawMessage{"e1": json.RawMessage(`{}`)},
	}
	rekor := &stubRekor{failOnce: true}
	m := &Mirror{CTN: ctn, Rekor: rekor, State: State{UUIDs: map[string]string{}}, StatePath: filepath.Join(dir, "s.json")}
	if _, err := m.Tick(context.Background()); err == nil {
		t.Fatal("expected error on rekor failure")
	}
	if m.State.LastMirroredSeq != 0 {
		t.Errorf("seq should not advance on rekor failure, got %d", m.State.LastMirroredSeq)
	}
	if _, ok := m.State.UUIDs["e1"]; ok {
		t.Error("uuid should not be recorded on rekor failure")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	in := State{LastMirroredSeq: 99, UUIDs: map[string]string{"e1": "u1", "e2": "u2"}}
	if err := saveState(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.LastMirroredSeq != 99 || out.UUIDs["e1"] != "u1" || out.UUIDs["e2"] != "u2" {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}

func TestLoadStateMissing(t *testing.T) {
	out, err := loadState(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if out.UUIDs == nil {
		t.Error("UUIDs map should be non-nil even on first run")
	}
}
