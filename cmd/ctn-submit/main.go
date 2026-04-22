// Command ctn-submit signs a conformance SuiteReport JSON document with an
// ed25519 key and POSTs it to a CTN endpoint. Distributed to design partners
// as the literal one-liner referenced in the partner-onboarding kit
// (docs/cncf/ctn-design-partners.md).
//
// Usage:
//
//	ctn-submit \
//	    -endpoint https://staging.ctn.openjobspec.org \
//	    -key-id   did:web:example.com:keys:postgres-2026 \
//	    -seed-file ~/.ctn/seed.bin \
//	    -report   ./conformance-report.json
//
// The seed file MUST be 32 bytes (the ed25519 seed). Generate one with:
//
//	dd if=/dev/urandom of=seed.bin bs=32 count=1
//
// The signed payload is the canonical JSON of the report. P1 uses
// json.Marshal output as the canonicalization; P2 will switch to RFC 8785.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

const version = "0.1.0"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Println("ctn-submit", version)
		return
	}

	endpoint := flag.String("endpoint", "", "CTN base URL (e.g. https://staging.ctn.openjobspec.org)")
	keyID := flag.String("key-id", "", "submitter key ID (e.g. did:web:example.com:keys:backend-2026)")
	seedFile := flag.String("seed-file", "", "path to a 32-byte ed25519 seed file")
	reportPath := flag.String("report", "", "path to SuiteReport JSON file (use - for stdin)")
	sigAlg := flag.String("sig-alg", "ed25519", "signature algorithm: ed25519, ml-dsa-65, or hybrid")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	dryRun := flag.Bool("dry-run", false, "print the signed submission instead of POSTing it")
	flag.Parse()

	if err := run(*endpoint, *keyID, *seedFile, *reportPath, *sigAlg, *timeout, *dryRun); err != nil {
		fmt.Fprintln(os.Stderr, "ctn-submit:", err)
		os.Exit(1)
	}
}

func run(endpoint, keyID, seedFile, reportPath, sigAlg string, timeout time.Duration, dryRun bool) error {
	config := submitConfig{
		endpoint:   endpoint,
		keyID:      keyID,
		seedFile:   seedFile,
		reportPath: reportPath,
		sigAlg:     sigAlg,
		timeout:    timeout,
		dryRun:     dryRun,
	}
	return executeSubmit(config, defaultSubmitEnvironment())
}
