package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func mustOpen(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func sampleSub(t *testing.T) Submission {
	t.Helper()
	return Submission{
		Report:             json.RawMessage(`{"test_suite_version":"x","conformant":true}`),
		SubmitterSignature: "deadbeef",
		SubmitterKeyID:     "did:web:example.com:keys:postgres-2026",
	}
}

func TestAppendAndGet(t *testing.T) {
	s, _ := mustOpen(t)
	ctx := context.Background()

	e, err := s.Append(ctx, sampleSub(t))
	if err != nil {
		t.Fatal(err)
	}
	if e.SequenceNumber != 1 || e.EntryID == "" || e.ReportSHA256 == "" {
		t.Errorf("entry not populated: %+v", e)
	}
	got, err := s.Get(ctx, e.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntryID != e.EntryID {
		t.Errorf("Get mismatch")
	}
}

func TestAppendValidation(t *testing.T) {
	s, _ := mustOpen(t)
	ctx := context.Background()

	cases := []Submission{
		{},
		{Report: json.RawMessage(`{}`)},
		{Report: json.RawMessage(`{}`), SubmitterKeyID: "k"},
	}
	for i, sub := range cases {
		if _, err := s.Append(ctx, sub); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestHeadAdvances(t *testing.T) {
	s, _ := mustOpen(t)
	ctx := context.Background()

	if h := s.Head(ctx); h.SequenceNumber != 0 {
		t.Errorf("empty head should have seq 0, got %d", h.SequenceNumber)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.Append(ctx, sampleSub(t)); err != nil {
			t.Fatal(err)
		}
	}
	h := s.Head(ctx)
	if h.SequenceNumber != 5 {
		t.Errorf("expected seq 5, got %d", h.SequenceNumber)
	}
	if h.LastEntryID == "" || h.LastEntrySHA == "" {
		t.Errorf("head missing fields: %+v", h)
	}
}

func TestReplayPreservesEntries(t *testing.T) {
	s, path := mustOpen(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.Append(ctx, sampleSub(t)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Count() != 3 {
		t.Errorf("expected 3 replayed entries, got %d", s2.Count())
	}
	if s2.Head(ctx).SequenceNumber != 3 {
		t.Errorf("replayed head wrong")
	}
	// Append after replay must continue numbering.
	e, err := s2.Append(ctx, sampleSub(t))
	if err != nil {
		t.Fatal(err)
	}
	if e.SequenceNumber != 4 {
		t.Errorf("expected seq 4 after replay, got %d", e.SequenceNumber)
	}
}
