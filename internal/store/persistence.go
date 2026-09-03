package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// cosigLine is the durable shape of a cosignature record. The envelope
// distinguishes it from entry records without changing existing entry bytes.
type cosigLine struct {
	Cosig struct {
		EntryID          string    `json:"entry_id"`
		WitnessKeyID     string    `json:"witness_key_id"`
		WitnessSignature string    `json:"witness_signature"`
		CosignedAt       time.Time `json:"cosigned_at"`
	} `json:"cosig"`
}

type replayRecord struct {
	entry        *Entry
	cosignature  *replayedCosignature
	entryLineSHA string
}

type replayedCosignature struct {
	entryID string
	value   WitnessCosignature
}

type durableFile interface {
	io.Writer
	Sync() error
	Truncate(size int64) error
	Close() error
}

type appendLog struct {
	file   durableFile
	writer *bufio.Writer
	size   int64
}

func openAppendLog(path string) (*appendLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return newAppendLog(f, info.Size()), nil
}

func newAppendLog(file durableFile, size int64) *appendLog {
	return &appendLog{
		file:   file,
		writer: bufio.NewWriter(file),
		size:   size,
	}
}

func (l *appendLog) Append(line []byte) error {
	record := append(append([]byte{}, line...), '\n')
	start := l.size
	if _, err := l.writer.Write(record); err != nil {
		return l.rollback(start, err)
	}
	if err := l.writer.Flush(); err != nil {
		return l.rollback(start, err)
	}
	if err := l.file.Sync(); err != nil {
		return l.rollback(start, err)
	}
	l.size += int64(len(record))
	return nil
}

func (l *appendLog) rollback(size int64, cause error) error {
	// A failed bufio flush retains unwritten bytes. Reset first so a retry
	// cannot append stale bytes after the durable file is restored.
	l.writer.Reset(l.file)
	if err := l.file.Truncate(size); err != nil {
		return errors.Join(cause, fmt.Errorf("rollback ledger append: %w", err))
	}
	if err := l.file.Sync(); err != nil {
		return errors.Join(cause, fmt.Errorf("sync ledger rollback: %w", err))
	}
	l.size = size
	return cause
}

func (l *appendLog) Close() error {
	return errors.Join(l.writer.Flush(), l.file.Close())
}

func encodeEntry(entry Entry) ([]byte, string, error) {
	line, err := json.Marshal(&entry)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(line)
	return line, hex.EncodeToString(hash[:]), nil
}

func encodeCosignature(entryID string, cosig WitnessCosignature) ([]byte, error) {
	var line cosigLine
	line.Cosig.EntryID = entryID
	line.Cosig.WitnessKeyID = cosig.WitnessKeyID
	line.Cosig.WitnessSignature = cosig.WitnessSignature
	line.Cosig.CosignedAt = cosig.CosignedAt
	return json.Marshal(line)
}

func replayLedger(path string) ([]replayRecord, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []replayRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		record, err := decodeReplayRecord(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", err.recordType, lineNum, err.cause)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	return records, nil
}

type replayDecodeError struct {
	recordType string
	cause      error
}

func decodeReplayRecord(line []byte) (replayRecord, *replayDecodeError) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(line, &probe); err != nil {
		return replayRecord{}, &replayDecodeError{recordType: "corrupt ledger", cause: err}
	}
	if _, isCosig := probe["cosig"]; isCosig {
		var durable cosigLine
		if err := json.Unmarshal(line, &durable); err != nil {
			return replayRecord{}, &replayDecodeError{recordType: "corrupt cosig", cause: err}
		}
		return replayRecord{
			cosignature: &replayedCosignature{
				entryID: durable.Cosig.EntryID,
				value: WitnessCosignature{
					WitnessKeyID:     durable.Cosig.WitnessKeyID,
					WitnessSignature: durable.Cosig.WitnessSignature,
					CosignedAt:       durable.Cosig.CosignedAt,
				},
			},
		}, nil
	}

	var entry Entry
	if err := json.Unmarshal(line, &entry); err != nil {
		return replayRecord{}, &replayDecodeError{recordType: "corrupt ledger", cause: err}
	}
	hash := sha256.Sum256(append([]byte{}, line...))
	return replayRecord{
		entry:        &entry,
		entryLineSHA: hex.EncodeToString(hash[:]),
	}, nil
}
