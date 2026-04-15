// Package e2e exercises ctn-verify end-to-end: submit a signed report
// via ctn-submit, then run the ctn-verify binary against the resulting
// entry. If both binaries succeed against the same in-memory CTN and
// the signature verifies, the auditor pipeline is real.
package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openjobspec/ojs-ctn/internal/api"
	"github.com/openjobspec/ojs-ctn/internal/store"
)

func buildBin(t *testing.T, pkg, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

func TestEndToEndSubmitThenVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in -short mode")
	}
	tmp := t.TempDir()

	st, err := store.Open(filepath.Join(tmp, "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer((&api.Server{Store: st}).Routes())
	defer srv.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()
	seedFile := filepath.Join(tmp, "seed.bin")
	if err := os.WriteFile(seedFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	keyID := "did:web:example.com:keys:test-1"
	trust := map[string]string{keyID: base64.StdEncoding.EncodeToString(pub)}
	trustBytes, _ := json.Marshal(trust)
	trustFile := filepath.Join(tmp, "trust.json")
	if err := os.WriteFile(trustFile, trustBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	report := map[string]any{
		"test_suite_version":    "test-1.0",
		"report_schema_version": "1.1.0",
		"target":                "http://example.com",
		"conformant":            true,
	}
	reportBytes, _ := json.Marshal(report)
	reportFile := filepath.Join(tmp, "report.json")
	if err := os.WriteFile(reportFile, reportBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	submitBin := buildBin(t, "github.com/openjobspec/ojs-ctn/cmd/ctn-submit", "ctn-submit")
	verifyBin := buildBin(t, "github.com/openjobspec/ojs-ctn/cmd/ctn-verify", "ctn-verify")

	cmd := exec.Command(submitBin,
		"-endpoint", srv.URL,
		"-key-id", keyID,
		"-seed-file", seedFile,
		"-report", reportFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ctn-submit failed: %v\n%s", err, out)
	}
	var entry struct {
		EntryID string `json:"entry_id"`
	}
	if err := json.Unmarshal(out, &entry); err != nil {
		t.Fatalf("decode submit response: %v\n%s", err, out)
	}
	if entry.EntryID == "" {
		t.Fatalf("no entry_id in response: %s", out)
	}

	cmd = exec.Command(verifyBin,
		"-endpoint", srv.URL,
		"-entry-id", entry.EntryID,
		"-trust-file", trustFile,
	)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ctn-verify failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Fatalf("expected OK in output, got: %s", out)
	}

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	wrongTrust, _ := json.Marshal(map[string]string{keyID: base64.StdEncoding.EncodeToString(wrongPub)})
	wrongFile := filepath.Join(tmp, "wrong.json")
	_ = os.WriteFile(wrongFile, wrongTrust, 0o600)
	cmd = exec.Command(verifyBin,
		"-endpoint", srv.URL,
		"-entry-id", entry.EntryID,
		"-trust-file", wrongFile,
	)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail with wrong key, got success: %s", out)
	}
	if !strings.Contains(string(out), "FAILED") && !strings.Contains(string(out), "verification") {
		t.Fatalf("expected signature failure message, got: %s", out)
	}

	emptyTrust, _ := json.Marshal(map[string]string{"did:web:other:keys:x": base64.StdEncoding.EncodeToString(pub)})
	emptyFile := filepath.Join(tmp, "empty.json")
	_ = os.WriteFile(emptyFile, emptyTrust, 0o600)
	cmd = exec.Command(verifyBin,
		"-endpoint", srv.URL,
		"-entry-id", entry.EntryID,
		"-trust-file", emptyFile,
	)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail with unknown key, got: %s", out)
	}
	if !strings.Contains(string(out), "not in trust file") {
		t.Fatalf("expected unknown-key message, got: %s", out)
	}
}
