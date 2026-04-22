package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func decodeEntry(body []byte, requestedID string) (Entry, error) {
	var entry Entry
	if err := json.Unmarshal(body, &entry); err != nil {
		return Entry{}, fmt.Errorf("decode entry: %w", err)
	}
	if entry.EntryID != requestedID {
		return Entry{}, fmt.Errorf("entry id mismatch: requested %q, got %q", requestedID, entry.EntryID)
	}
	if len(entry.Report) == 0 {
		return Entry{}, errors.New("entry has empty report")
	}
	return entry, nil
}

func verifyReportDigest(entry Entry) error {
	sum := sha256.Sum256(entry.Report)
	computed := hex.EncodeToString(sum[:])
	if !strings.EqualFold(computed, entry.ReportSHA256) {
		return fmt.Errorf("report_sha256 mismatch: declared %q, computed %q", entry.ReportSHA256, computed)
	}
	return nil
}

func verifyFreshness(entry Entry, freshness time.Duration) error {
	if freshness <= 0 {
		return nil
	}
	age := time.Since(entry.LoggedAt)
	if age > freshness {
		return fmt.Errorf("entry too old: logged %s ago, max %s", age.Round(time.Second), freshness)
	}
	return nil
}

func verifySignature(entry Entry, trust map[string]ed25519.PublicKey) error {
	publicKey, ok := trust[entry.SubmitterKeyID]
	if !ok {
		return fmt.Errorf("submitter key %q not in trust file", entry.SubmitterKeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(entry.SubmitterSignature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	canonical, err := canonicalize(entry.Report)
	if err != nil {
		return fmt.Errorf("canonicalize report: %w", err)
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("signature verification FAILED")
	}
	return nil
}
