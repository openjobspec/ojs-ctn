// Command ctn-witness is the third-party-witness companion to
// ctn-submit. A witness pulls a logged entry, recomputes the canonical
// report bytes, signs them with its own ed25519 key, and POSTs the
// cosignature back to the ledger. Multiple witnesses can cosign the
// same entry.
//
// Witnesses MUST NOT trust the submitter's signature blindly: a real
// witness re-runs the conformance suite against the submitter's target
// and only cosigns if its own results match. ctn-witness implements
// the cryptographic half — the operational decision is left to the
// witness's own pipeline.
//
// Usage:
//
//	ctn-witness \
//	    -endpoint     https://staging.ctn.openjobspec.org \
//	    -entry-id     01HXXXXXXXXXXXXXXXXXXXXXXX \
//	    -witness-key-id did:web:cncf.io:keys:ctn-witness-2026 \
//	    -seed-file    ~/.ctn/witness-seed.bin
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
		fmt.Println("ctn-witness", version)
		return
	}

	endpoint := flag.String("endpoint", "", "CTN base URL")
	entryID := flag.String("entry-id", "", "entry to cosign")
	keyID := flag.String("witness-key-id", "", "witness key ID")
	seedFile := flag.String("seed-file", "", "path to a 32-byte ed25519 seed file")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	dryRun := flag.Bool("dry-run", false, "print the cosignature instead of POSTing it")
	flag.Parse()

	if err := run(*endpoint, *entryID, *keyID, *seedFile, *timeout, *dryRun); err != nil {
		fmt.Fprintln(os.Stderr, "ctn-witness:", err)
		os.Exit(1)
	}
}

// Entry mirrors the server's response shape — duplicated here to keep
// ctn-witness independent from the server's internal package, exactly
// as ctn-verify does.
type Entry struct {
	EntryID            string          `json:"entry_id"`
	Report             json.RawMessage `json:"report"`
	SubmitterKeyID     string          `json:"submitter_key_id"`
	SubmitterSignature string          `json:"submitter_signature"`
}

func run(endpoint, entryID, keyID, seedFile string, timeout time.Duration, dryRun bool) error {
	if endpoint == "" {
		return errors.New("-endpoint required")
	}
	if entryID == "" {
		return errors.New("-entry-id required")
	}
	if keyID == "" {
		return errors.New("-witness-key-id required")
	}
	if seedFile == "" {
		return errors.New("-seed-file required")
	}
	seed, err := os.ReadFile(seedFile)
	if err != nil {
		return fmt.Errorf("read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 1. Fetch the entry.
	getURL := strings.TrimRight(endpoint, "/") + "/v1/entries/" + entryID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ctn-witness/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("get entry: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("get entry: server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var entry Entry
	if err := json.Unmarshal(body, &entry); err != nil {
		return fmt.Errorf("decode entry: %w", err)
	}
	if len(entry.Report) == 0 {
		return errors.New("entry has empty report")
	}

	// 2. Re-canonicalize report bytes the same way ctn-submit/ctn-verify do.
	var v any
	if err := json.Unmarshal(entry.Report, &v); err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}

	// 3. Cosign.
	sig := ed25519.Sign(priv, canon)
	cosig := map[string]string{
		"witness_key_id":    keyID,
		"witness_signature": base64.StdEncoding.EncodeToString(sig),
	}
	cosigBody, err := json.Marshal(cosig)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Println(string(cosigBody))
		return nil
	}

	// 4. POST.
	postURL := strings.TrimRight(endpoint, "/") + "/v1/entries/" + entryID + "/witness"
	preq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(cosigBody))
	if err != nil {
		return err
	}
	preq.Header.Set("Content-Type", "application/json")
	preq.Header.Set("User-Agent", "ctn-witness/"+version)
	presp, err := http.DefaultClient.Do(preq)
	if err != nil {
		return fmt.Errorf("post cosignature: %w", err)
	}
	defer presp.Body.Close()
	prb, _ := io.ReadAll(io.LimitReader(presp.Body, 1<<20))
	if presp.StatusCode/100 != 2 {
		return fmt.Errorf("server returned %d: %s", presp.StatusCode, strings.TrimSpace(string(prb)))
	}
	fmt.Println(string(prb))
	return nil
}
