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

	sigalgpkg "github.com/openjobspec/ojs-ctn/internal/sigalg"
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
	if keyID == "" {
		return errors.New("-key-id required")
	}
	if seedFile == "" {
		return errors.New("-seed-file required")
	}
	if reportPath == "" {
		return errors.New("-report required (use - for stdin)")
	}
	if !dryRun && endpoint == "" {
		return errors.New("-endpoint required (or use -dry-run)")
	}

	seed, err := os.ReadFile(seedFile)
	if err != nil {
		return fmt.Errorf("read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed must be exactly %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	report, err := readReport(reportPath)
	if err != nil {
		return err
	}

	var probe map[string]any
	if err := json.Unmarshal(report, &probe); err != nil {
		return fmt.Errorf("report is not valid JSON: %w", err)
	}

	// Canonicalize: re-marshal so whitespace differences don't change the
	// signature. P1 uses encoding/json's deterministic key ordering; P2
	// upgrades to RFC 8785 JCS.
	canon, err := json.Marshal(probe)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}

	var sigB64 string
	switch sigAlg {
	case "ed25519", "":
		priv := ed25519.NewKeyFromSeed(seed)
		signature := ed25519.Sign(priv, canon)
		sigB64 = base64.StdEncoding.EncodeToString(signature)
	case "ml-dsa-65":
		_, priv, err := sigalgpkg.GenerateMLDSA65Key(seed)
		if err != nil {
			return fmt.Errorf("keygen: %w", err)
		}
		sig, err := sigalgpkg.SignMLDSA65(priv, canon)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		sigB64 = base64.StdEncoding.EncodeToString(sig)
	case "hybrid":
		// Ed25519 + ML-DSA-65 hybrid
		edPriv := ed25519.NewKeyFromSeed(seed)
		edSig := ed25519.Sign(edPriv, canon)
		_, pqPriv, err := sigalgpkg.GenerateMLDSA65Key(seed)
		if err != nil {
			return fmt.Errorf("pq keygen: %w", err)
		}
		pqSig, err := sigalgpkg.SignMLDSA65(pqPriv, canon)
		if err != nil {
			return fmt.Errorf("pq sign: %w", err)
		}
		hybridSig, err := sigalgpkg.EncodeHybridSig(edSig, pqSig)
		if err != nil {
			return fmt.Errorf("hybrid encode: %w", err)
		}
		sigB64 = base64.StdEncoding.EncodeToString(hybridSig)
	default:
		return fmt.Errorf("unknown sig-alg %q (use ed25519, ml-dsa-65, or hybrid)", sigAlg)
	}

	submission := map[string]any{
		"report":              json.RawMessage(canon),
		"submitter_signature": sigB64,
		"submitter_key_id":    keyID,
	}

	body, err := json.Marshal(submission)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Println(string(body))
		return nil
	}

	url := strings.TrimRight(endpoint, "/") + "/v1/submissions"
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ctn-submit/"+version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	fmt.Println(string(respBody))
	return nil
}

func readReport(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	}
	return os.ReadFile(path)
}
