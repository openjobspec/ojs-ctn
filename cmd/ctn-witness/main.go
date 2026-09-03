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
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	config := witnessConfig{
		endpoint: endpoint,
		entryID:  entryID,
		keyID:    keyID,
		seedFile: seedFile,
		timeout:  timeout,
		dryRun:   dryRun,
	}
	return executeWitness(config, defaultWitnessEnvironment())
}
