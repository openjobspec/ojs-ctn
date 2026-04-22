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
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	writeVerificationSuccess(os.Stdout)
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
	config := verifyConfig{
		endpoint:    endpoint,
		entryID:     entryID,
		trustFile:   trustFile,
		timeout:     timeout,
		freshness:   freshness,
		allowAnyKey: allowAnyKey,
	}
	return executeVerify(config, defaultVerifyEnvironment())
}
