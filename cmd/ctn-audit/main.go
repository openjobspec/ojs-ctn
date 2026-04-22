// Command ctn-audit is the auditor-facing dashboard CLI for a CTN log.
// Where ctn-verify checks one entry, ctn-audit walks the whole tail
// and produces a structured report:
//
//   - Total entries seen, sequence number range, time window.
//   - Per-submitter key ID counts.
//   - Witness-cosignature coverage (% of entries with >=1, >=2 witnesses).
//   - Verification breakdown: signed-ok / unknown-key / bad-sig.
//   - Optional gap detection: missing or out-of-order sequence numbers.
//
// Output is text by default and JSON with -json (pipe-friendly for
// alerting). Exit code is 0 if no errors *and* the witness coverage
// floor (configurable, default 0%) is met, 2 otherwise.
//
// This is the M5 deliverable that was promised in the moonshot brief
// as the "auditor dashboard", scoped down to a CLI so it ships in this
// session and a future Studio panel can wrap the same report shape.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if err := mainErr(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ctn-audit:", err)
		os.Exit(1)
	}
}

func mainErr(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ctn-audit", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "CTN base URL")
	limit := fs.Int("limit", 1000, "max entries to audit (walks newest-first by sequence number)")
	jsonOut := fs.Bool("json", false, "emit JSON report instead of text")
	trustFile := fs.String("trust-file", "", "optional submitter trust file (key_id → base64 ed25519 pubkey)")
	requiredCoverage := fs.Float64("required-witness-coverage", 0.0, "exit non-zero if <coverage of entries have >=1 witness, in [0,1]")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout per request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return errors.New("-endpoint required")
	}
	if *requiredCoverage < 0 || *requiredCoverage > 1 {
		return errors.New("-required-witness-coverage must be in [0,1]")
	}

	trust, err := loadTrust(*trustFile)
	if err != nil {
		return fmt.Errorf("load trust: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*time.Duration(*limit/100+5))
	defer cancel()
	client := &http.Client{Timeout: *timeout}

	h, err := fetchHead(ctx, client, *endpoint)
	if err != nil {
		return fmt.Errorf("fetch head: %w", err)
	}
	entries, err := fetchTail(ctx, client, *endpoint, h.Size, *limit)
	if err != nil {
		return fmt.Errorf("fetch tail: %w", err)
	}

	report := analyse(*endpoint, h, entries, trust, *requiredCoverage)
	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printText(out, report)
	}
	if !report.Healthy {
		os.Exit(2)
	}
	return nil
}
