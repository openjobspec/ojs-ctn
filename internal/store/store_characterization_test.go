package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDurableEntryAndCosignatureBytes(t *testing.T) {
	s, path := mustOpen(t)
	ctx := context.Background()
	sub := Submission{
		Report:             json.RawMessage("{\n  \"backend\": {\"name\": \"postgres\"},\n  \"conformant\": true\n}"),
		SubmitterSignature: "submitter-signature",
		SubmitterKeyID:     "submitter-key",
	}

	entry, err := s.Append(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	entryLine, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, entryLine...), '\n')
	assertFileBytes(t, path, want)

	headBeforeCosign := s.Head(ctx)
	cosigned, err := s.Cosign(ctx, entry.EntryID, "witness-key", "witness-signature")
	if err != nil {
		t.Fatal(err)
	}
	if len(cosigned.WitnessCosignatures) != 1 {
		t.Fatalf("cosignatures = %d, want 1", len(cosigned.WitnessCosignatures))
	}

	var persisted cosigLine
	persisted.Cosig.EntryID = entry.EntryID
	persisted.Cosig.WitnessKeyID = "witness-key"
	persisted.Cosig.WitnessSignature = "witness-signature"
	persisted.Cosig.CosignedAt = cosigned.WitnessCosignatures[0].CosignedAt
	cosigBytes, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, cosigBytes...)
	want = append(want, '\n')
	assertFileBytes(t, path, want)

	lineHash := sha256.Sum256(entryLine)
	wantHash := hex.EncodeToString(lineHash[:])
	if headBeforeCosign.LastEntrySHA != wantHash {
		t.Fatalf("head hash = %q, want %q", headBeforeCosign.LastEntrySHA, wantHash)
	}
	headAfterCosign := s.Head(ctx)
	if headAfterCosign.LastEntrySHA != headBeforeCosign.LastEntrySHA {
		t.Fatalf("cosign changed head hash from %q to %q", headBeforeCosign.LastEntrySHA, headAfterCosign.LastEntrySHA)
	}
	if headAfterCosign.SequenceNumber != headBeforeCosign.SequenceNumber {
		t.Fatalf("cosign changed sequence from %d to %d", headBeforeCosign.SequenceNumber, headAfterCosign.SequenceNumber)
	}
}

func TestReplayCosignatureReplacementToleranceAndSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	loggedAt := time.Date(2026, 4, 18, 12, 0, 0, 123, time.UTC)
	entry := Entry{
		EntryID:            "entry-1",
		LoggedAt:           loggedAt,
		ReportSHA256:       "report-hash",
		Report:             json.RawMessage(`{"backend":{"name":"postgres"}}`),
		SubmitterSignature: "submitter-signature",
		SubmitterKeyID:     "submitter-key",
		SequenceNumber:     1,
	}
	entryLine := mustJSON(t, entry)

	orphan := newCosigLine("missing-entry", "orphan", "ignored", loggedAt.Add(time.Second))
	first := newCosigLine(entry.EntryID, "witness-a", "first", loggedAt.Add(2*time.Second))
	replacement := newCosigLine(entry.EntryID, "witness-a", "replacement", loggedAt.Add(3*time.Second))
	second := newCosigLine(entry.EntryID, "witness-b", "second", loggedAt.Add(4*time.Second))

	var ledger bytes.Buffer
	for _, line := range [][]byte{entryLine, {}, mustJSON(t, orphan), mustJSON(t, first), mustJSON(t, replacement), mustJSON(t, second)} {
		ledger.Write(line)
		ledger.WriteByte('\n')
	}
	if err := os.WriteFile(path, ledger.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := s.Get(context.Background(), entry.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.WitnessCosignatures) != 2 {
		t.Fatalf("cosignatures = %d, want 2", len(got.WitnessCosignatures))
	}
	if got.WitnessCosignatures[0].WitnessKeyID != "witness-a" ||
		got.WitnessCosignatures[0].WitnessSignature != "replacement" ||
		!got.WitnessCosignatures[0].CosignedAt.Equal(loggedAt.Add(3*time.Second)) {
		t.Fatalf("replacement cosignature = %+v", got.WitnessCosignatures[0])
	}
	if got.WitnessCosignatures[1].WitnessKeyID != "witness-b" ||
		got.WitnessCosignatures[1].WitnessSignature != "second" {
		t.Fatalf("second cosignature = %+v", got.WitnessCosignatures[1])
	}

	hash := sha256.Sum256(entryLine)
	head := s.Head(context.Background())
	if head.SequenceNumber != 1 || head.LastEntryID != entry.EntryID ||
		head.LastEntrySHA != hex.EncodeToString(hash[:]) {
		t.Fatalf("replayed head = %+v", head)
	}

	next, err := s.Append(context.Background(), sampleSub(t))
	if err != nil {
		t.Fatal(err)
	}
	if next.SequenceNumber != 2 {
		t.Fatalf("sequence after replay = %d, want 2", next.SequenceNumber)
	}
}

func TestReplayRejectsCorruptRecords(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "entry", content: "{not-json}\n", wantErr: "corrupt ledger line 1:"},
		{name: "cosignature", content: `{"cosig":"not-an-object"}` + "\n", wantErr: "corrupt cosig line 1:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ledger.jsonl")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Open error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestReturnedCosignatureSlicesAreDefensive(t *testing.T) {
	s, _ := mustOpen(t)
	ctx := context.Background()
	entry, err := s.Append(ctx, Submission{
		Report:             json.RawMessage(`{"backend":{"name":"postgres"}}`),
		SubmitterSignature: "submitter-signature",
		SubmitterKeyID:     "submitter-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	cosigned, err := s.Cosign(ctx, entry.EntryID, "witness-a", "signature-a")
	if err != nil {
		t.Fatal(err)
	}
	cosigned.WitnessCosignatures[0].WitnessSignature = "mutated-cosign-result"

	got, err := s.Get(ctx, entry.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WitnessCosignatures[0].WitnessSignature != "signature-a" {
		t.Fatalf("Get observed caller mutation: %+v", got.WitnessCosignatures)
	}
	got.WitnessCosignatures[0].WitnessSignature = "mutated-get-result"

	listed := s.List(ListOptions{Limit: 1})
	if listed.Entries[0].WitnessCosignatures[0].WitnessSignature != "signature-a" {
		t.Fatalf("List observed caller mutation: %+v", listed.Entries[0].WitnessCosignatures)
	}
	listed.Entries[0].WitnessCosignatures[0].WitnessSignature = "mutated-list-result"

	backendEntries := s.EntriesForBackend("postgres")
	if backendEntries[0].WitnessCosignatures[0].WitnessSignature != "signature-a" {
		t.Fatalf("EntriesForBackend observed caller mutation: %+v", backendEntries[0].WitnessCosignatures)
	}
}

func TestAppendFlushFailureRollsBackDurableAndIndexedState(t *testing.T) {
	flushErr := errors.New("flush failed")
	file := &failureFile{writeErr: flushErr}
	s := newStore(newAppendLog(file, 0), newLedgerIndex(nil))

	if _, err := s.Append(context.Background(), sampleSub(t)); !errors.Is(err, flushErr) {
		t.Fatalf("Append error = %v, want %v", err, flushErr)
	}
	if s.Count() != 0 || len(file.data) != 0 {
		t.Fatalf("failed append state: count=%d bytes=%q", s.Count(), file.data)
	}
	if want := []string{"write", "truncate", "sync"}; !reflect.DeepEqual(file.calls, want) {
		t.Fatalf("failure calls = %v, want %v", file.calls, want)
	}

	file.writeErr = nil
	file.calls = nil
	entry, err := s.Append(context.Background(), sampleSub(t))
	if err != nil {
		t.Fatal(err)
	}
	if entry.SequenceNumber != 1 || s.Count() != 1 {
		t.Fatalf("retry state: entry=%+v count=%d", entry, s.Count())
	}
	if want := []string{"write", "sync"}; !reflect.DeepEqual(file.calls, want) {
		t.Fatalf("retry calls = %v, want %v", file.calls, want)
	}
}

func TestAppendSyncFailureRollsBackBeforeRetry(t *testing.T) {
	syncErr := errors.New("sync failed")
	file := &failureFile{syncErrors: []error{syncErr, nil}}
	s := newStore(newAppendLog(file, 0), newLedgerIndex(nil))

	if _, err := s.Append(context.Background(), sampleSub(t)); !errors.Is(err, syncErr) {
		t.Fatalf("Append error = %v, want %v", err, syncErr)
	}
	if s.Count() != 0 || len(file.data) != 0 {
		t.Fatalf("failed append state: count=%d bytes=%q", s.Count(), file.data)
	}
	if want := []string{"write", "sync", "truncate", "sync"}; !reflect.DeepEqual(file.calls, want) {
		t.Fatalf("failure calls = %v, want %v", file.calls, want)
	}

	file.calls = nil
	entry, err := s.Append(context.Background(), sampleSub(t))
	if err != nil {
		t.Fatal(err)
	}
	if entry.SequenceNumber != 1 {
		t.Fatalf("retry sequence = %d, want 1", entry.SequenceNumber)
	}
}

func TestCosignFailureDoesNotMutateIndexOrDurableBytes(t *testing.T) {
	file := &failureFile{}
	s := newStore(newAppendLog(file, 0), newLedgerIndex(nil))
	entry, err := s.Append(context.Background(), sampleSub(t))
	if err != nil {
		t.Fatal(err)
	}
	entryBytes := append([]byte(nil), file.data...)

	syncErr := errors.New("sync failed")
	file.syncErrors = []error{syncErr, nil}
	if _, err := s.Cosign(context.Background(), entry.EntryID, "witness", "signature"); !errors.Is(err, syncErr) {
		t.Fatalf("Cosign error = %v, want %v", err, syncErr)
	}
	got, err := s.Get(context.Background(), entry.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.WitnessCosignatures) != 0 {
		t.Fatalf("failed cosign mutated index: %+v", got.WitnessCosignatures)
	}
	if !bytes.Equal(file.data, entryBytes) {
		t.Fatalf("failed cosign bytes = %q, want %q", file.data, entryBytes)
	}

	cosigned, err := s.Cosign(context.Background(), entry.EntryID, "witness", "signature")
	if err != nil {
		t.Fatal(err)
	}
	if len(cosigned.WitnessCosignatures) != 1 {
		t.Fatalf("retry cosignatures = %+v", cosigned.WitnessCosignatures)
	}
}

func TestAppendPropagatesRollbackFailure(t *testing.T) {
	syncErr := errors.New("sync failed")
	truncateErr := errors.New("truncate failed")
	file := &failureFile{
		syncErrors:  []error{syncErr},
		truncateErr: truncateErr,
	}
	s := newStore(newAppendLog(file, 0), newLedgerIndex(nil))

	_, err := s.Append(context.Background(), sampleSub(t))
	if !errors.Is(err, syncErr) || !errors.Is(err, truncateErr) {
		t.Fatalf("Append error = %v, want sync and truncate failures", err)
	}
	if s.Count() != 0 {
		t.Fatalf("failed append count = %d, want 0", s.Count())
	}
}

func TestClosePropagatesFlushAndCloseFailures(t *testing.T) {
	flushErr := errors.New("flush failed")
	closeErr := errors.New("close failed")
	file := &failureFile{writeErr: flushErr, closeErr: closeErr}
	log := newAppendLog(file, 0)
	if _, err := log.writer.Write([]byte("pending")); err != nil {
		t.Fatal(err)
	}

	err := log.Close()
	if !errors.Is(err, flushErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Close error = %v, want flush and close failures", err)
	}
}

func newCosigLine(entryID, witnessKeyID, signature string, at time.Time) cosigLine {
	var line cosigLine
	line.Cosig.EntryID = entryID
	line.Cosig.WitnessKeyID = witnessKeyID
	line.Cosig.WitnessSignature = signature
	line.Cosig.CosignedAt = at
	return line
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file bytes:\n got %q\nwant %q", got, want)
	}
}

type failureFile struct {
	data        []byte
	writeErr    error
	syncErrors  []error
	truncateErr error
	closeErr    error
	calls       []string
}

func (f *failureFile) Write(p []byte) (int, error) {
	f.calls = append(f.calls, "write")
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.data = append(f.data, p...)
	return len(p), nil
}

func (f *failureFile) Sync() error {
	f.calls = append(f.calls, "sync")
	if len(f.syncErrors) == 0 {
		return nil
	}
	err := f.syncErrors[0]
	f.syncErrors = f.syncErrors[1:]
	return err
}

func (f *failureFile) Truncate(size int64) error {
	f.calls = append(f.calls, "truncate")
	if f.truncateErr != nil {
		return f.truncateErr
	}
	f.data = f.data[:size]
	return nil
}

func (f *failureFile) Close() error {
	f.calls = append(f.calls, "close")
	return f.closeErr
}
