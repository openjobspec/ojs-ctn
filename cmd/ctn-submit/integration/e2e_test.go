// Package e2e runs the full CTN flow end-to-end: spin up an in-memory
// CTN server, build the ctn-submit binary, sign a conformance report
// with a freshly-generated ed25519 keypair, post via the CLI, then read
// the entry back and verify the signature against the original report.
//
// This is the literal integration the design-partner kit promises will
// work. If this test passes, the partner kit is real.
package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openjobspec/ojs-ctn/internal/api"
	"github.com/openjobspec/ojs-ctn/internal/store"
)

func TestEndToEndSubmissionAndSignatureVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in -short mode")
	}

	tmp := t.TempDir()

	// 1. Server backed by a fresh ledger file.
	st, err := store.Open(filepath.Join(tmp, "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer((&api.Server{Store: st}).Routes())
	defer srv.Close()

	// 2. Fresh ed25519 keypair; write the 32-byte seed to disk.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()
	seedFile := filepath.Join(tmp, "seed.bin")
	if err := os.WriteFile(seedFile, seed, 0600); err != nil {
		t.Fatal(err)
	}

	// 3. Sample SuiteReport JSON — shape mirrors lib.SuiteReport v1.1.
	report := map[string]any{
		"test_suite_version":    "test-1.0",
		"report_schema_version": "1.1.0",
		"target":                "http://example.com",
		"conformant":            true,
		"conformant_level":      4,
		"environment": map[string]any{
			"os":   "linux",
			"arch": "amd64",
		},
	}
	reportFile := filepath.Join(tmp, "report.json")
	reportBytes, _ := json.Marshal(report)
	if err := os.WriteFile(reportFile, reportBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Build ctn-submit binary fresh.
	bin := filepath.Join(tmp, "ctn-submit")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ctn-submit")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ctn-submit: %v\n%s", err, out)
	}

	// 5. Run the CLI against the test server.
	keyID := "did:web:test.openjobspec.org:keys:e2e-2026"
	cmd := exec.Command(bin,
		"-endpoint", srv.URL,
		"-key-id", keyID,
		"-seed-file", seedFile,
		"-report", reportFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ctn-submit failed: %v\n%s", err, out)
	}

	// 6. Parse the returned entry.
	var entry struct {
		EntryID            string          `json:"entry_id"`
		ReportSHA256       string          `json:"report_sha256"`
		Report             json.RawMessage `json:"report"`
		SubmitterSignature string          `json:"submitter_signature"`
		SubmitterKeyID     string          `json:"submitter_key_id"`
	}
	if err := json.Unmarshal(out, &entry); err != nil {
		t.Fatalf("parse cli output: %v\noutput: %s", err, out)
	}
	if entry.SubmitterKeyID != keyID {
		t.Errorf("key id roundtrip wrong: got %q want %q", entry.SubmitterKeyID, keyID)
	}

	// 7. GET the entry back from the server (independent path).
	resp, err := http.Get(srv.URL + "/v1/entries/" + entry.EntryID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("entry GET status %d", resp.StatusCode)
	}
	var got struct {
		Report             json.RawMessage `json:"report"`
		SubmitterSignature string          `json:"submitter_signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}

	// 8. Verify the signature against the canonical re-marshal of the
	//    stored report — this is the verification path any third-party
	//    auditor will use.
	var probe map[string]any
	if err := json.Unmarshal(got.Report, &probe); err != nil {
		t.Fatal(err)
	}
	canon, _ := json.Marshal(probe)
	sig, err := base64.StdEncoding.DecodeString(got.SubmitterSignature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		t.Fatal("signature verification failed — the design-partner kit is broken")
	}

	// 9. Tampering must invalidate.
	tampered := append([]byte{}, canon...)
	tampered[len(tampered)-2] ^= 0xff
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatal("signature must reject tampered payload")
	}

	t.Logf("end-to-end OK: entry %s, sha256 %s", entry.EntryID, entry.ReportSHA256)
}

// repoRoot returns the repository root for the test binary path. We assume
// the test runs from inside the ojs-ctn module, which is where `go test`
// puts us by default.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// We're in .../ojs-ctn/cmd/ctn-submit/integration; walk up to ojs-ctn.
	if !strings.Contains(wd, "ojs-ctn") {
		t.Fatalf("unexpected working dir: %s", wd)
	}
	for filepath.Base(wd) != "ojs-ctn" {
		wd = filepath.Dir(wd)
	}
	return wd
}
