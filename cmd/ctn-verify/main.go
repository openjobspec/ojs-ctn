// Command ctn-verify is the auditor companion to ctn-submit. It pulls
// an entry from a CTN endpoint, looks the submitter's public key up in
// a local trust file, and verifies the ed25519 signature against the
// canonical bytes of the stored report.
//
// Usage:
//
//	ctn-verify \
//	    -endpoint   https://staging.ctn.openjobspec.org \
//	    -entry-id   01HXXXXXXXXXXXXXXXXXXXXXXX \
//	    -trust-file ./trust.json
//
// trust.json maps key IDs to base64-encoded ed25519 public keys:
//
//	{
//	  "did:web:example.com:keys:postgres-2026": "BASE64_ED25519_PUBKEY=="
//	}
//
// Exits 0 on a verified entry, non-zero otherwise. Designed to be
// embedded in a CI pipeline by an OJS adopter who wants to gate
// deployments on transparency-log inclusion.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const version = "0.1.0"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Println("ctn-verify", version)
		return
	}

	endpoint := flag.String("endpoint", "", "CTN base URL (e.g. https://staging.ctn.openjobspec.org)")
	entryID := flag.String("entry-id", "", "entry ID to verify")
	trustFile := flag.String("trust-file", "", "JSON file mapping key_id -> base64 ed25519 pubkey")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	freshness := flag.Duration("freshness", 0, "if >0, fail if entry was logged longer ago than this")
	allowAnyKey := flag.Bool("allow-any-key", false, "skip trust-file check and just verify structural integrity (DEV ONLY)")
	flag.Parse()

	if err := run(*endpoint, *entryID, *trustFile, *timeout, *freshness, *allowAnyKey); err != nil {
		fmt.Fprintln(os.Stderr, "ctn-verify:", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

// Entry mirrors ojs-ctn/internal/store.Entry. We duplicate it here on
// purpose: ctn-verify is the auditor binary and MUST NOT depend on the
// server's internal package — that would make it pointless to ship to
// adopters as an independent verifier.
type Entry struct {
	EntryID            string          `json:"entry_id"`
	LoggedAt           time.Time       `json:"logged_at"`
	ReportSHA256       string          `json:"report_sha256"`
	Report             json.RawMessage `json:"report"`
	SubmitterSignature string          `json:"submitter_signature"`
	SubmitterKeyID     string          `json:"submitter_key_id"`
	SequenceNumber     uint64          `json:"sequence_number"`
}

func run(endpoint, entryID, trustFile string, timeout, freshness time.Duration, allowAnyKey bool) error {
	if endpoint == "" {
		return errors.New("-endpoint required")
	}
	if entryID == "" {
		return errors.New("-entry-id required")
	}
	if trustFile == "" && !allowAnyKey {
		return errors.New("-trust-file required (or pass -allow-any-key for dev)")
	}

	trust, err := loadTrust(trustFile, allowAnyKey)
	if err != nil {
		return err
	}

	url := strings.TrimRight(endpoint, "/") + "/v1/entries/" + entryID
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ctn-verify/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var entry Entry
	if err := json.Unmarshal(body, &entry); err != nil {
		return fmt.Errorf("decode entry: %w", err)
	}
	if entry.EntryID != entryID {
		return fmt.Errorf("entry id mismatch: requested %q, got %q", entryID, entry.EntryID)
	}
	if len(entry.Report) == 0 {
		return errors.New("entry has empty report")
	}

	// Confirm the stored sha256 matches the report bytes we received.
	sum := sha256.Sum256(entry.Report)
	gotSHA := hex.EncodeToString(sum[:])
	if !strings.EqualFold(gotSHA, entry.ReportSHA256) {
		return fmt.Errorf("report_sha256 mismatch: declared %q, computed %q", entry.ReportSHA256, gotSHA)
	}

	if freshness > 0 {
		age := time.Since(entry.LoggedAt)
		if age > freshness {
			return fmt.Errorf("entry too old: logged %s ago, max %s", age.Round(time.Second), freshness)
		}
	}

	if allowAnyKey {
		fmt.Fprintln(os.Stderr, "ctn-verify: WARNING -allow-any-key set; signature NOT cryptographically verified against a trusted key")
		return nil
	}

	pub, ok := trust[entry.SubmitterKeyID]
	if !ok {
		return fmt.Errorf("submitter key %q not in trust file", entry.SubmitterKeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(entry.SubmitterSignature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	// Re-canonicalize report bytes the same way ctn-submit did, so a
	// proxy that re-formatted the JSON in transit can't break verify.
	canon, err := canonicalize(entry.Report)
	if err != nil {
		return fmt.Errorf("canonicalize report: %w", err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		return errors.New("signature verification FAILED")
	}
	return nil
}

func loadTrust(path string, allowAnyKey bool) (map[string]ed25519.PublicKey, error) {
	if path == "" && allowAnyKey {
		return map[string]ed25519.PublicKey{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust file: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse trust file: %w", err)
	}
	out := make(map[string]ed25519.PublicKey, len(m))
	for kid, b64 := range m {
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey for %q: %w", kid, err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pubkey for %q is %d bytes, want %d", kid, len(key), ed25519.PublicKeySize)
		}
		out[kid] = ed25519.PublicKey(key)
	}
	if len(out) == 0 {
		return nil, errors.New("trust file is empty")
	}
	return out, nil
}

// canonicalize matches ctn-submit's P1 strategy: json.Unmarshal into a
// generic value, then re-Marshal. Go's encoding/json sorts map keys
// alphabetically, which is enough determinism for P1. P2 will switch
// the whole pipeline to RFC 8785 JCS.
func canonicalize(raw json.RawMessage) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
