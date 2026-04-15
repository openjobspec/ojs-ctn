// Package e2e is the witness-flow end-to-end test: submitter signs and
// posts an entry, witness fetches and cosigns it, ctn-verify confirms
// the entry's submitter signature, then we manually verify the witness
// cosignature reads back from the entry. If the cosig roundtrips and
// validates, the trust-network witness pattern is real.
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

func TestWitnessCosignRoundtrip(t *testing.T) {
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

	// Submitter key.
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	subSeed := subPriv.Seed()
	subSeedFile := filepath.Join(tmp, "submitter.seed")
	_ = os.WriteFile(subSeedFile, subSeed, 0o600)

	// Witness key.
	witPub, witPriv, _ := ed25519.GenerateKey(rand.Reader)
	witSeed := witPriv.Seed()
	witSeedFile := filepath.Join(tmp, "witness.seed")
	_ = os.WriteFile(witSeedFile, witSeed, 0o600)

	// Report.
	report, _ := json.Marshal(map[string]any{
		"test_suite_version":    "test-1.0",
		"report_schema_version": "1.1.0",
		"target":                "http://example.com",
		"conformant":            true,
	})
	reportFile := filepath.Join(tmp, "report.json")
	_ = os.WriteFile(reportFile, report, 0o600)

	subKeyID := "did:web:example.com:keys:submit-1"
	witKeyID := "did:web:cncf.io:keys:witness-1"

	submitBin := buildBin(t, "github.com/openjobspec/ojs-ctn/cmd/ctn-submit", "ctn-submit")
	witnessBin := buildBin(t, "github.com/openjobspec/ojs-ctn/cmd/ctn-witness", "ctn-witness")
	verifyBin := buildBin(t, "github.com/openjobspec/ojs-ctn/cmd/ctn-verify", "ctn-verify")

	// Submit.
	out, err := exec.Command(submitBin,
		"-endpoint", srv.URL,
		"-key-id", subKeyID,
		"-seed-file", subSeedFile,
		"-report", reportFile,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("submit: %v\n%s", err, out)
	}
	var entry struct {
		EntryID string `json:"entry_id"`
	}
	if err := json.Unmarshal(out, &entry); err != nil {
		t.Fatalf("decode submit: %v\n%s", err, out)
	}

	// Cosign.
	out, err = exec.Command(witnessBin,
		"-endpoint", srv.URL,
		"-entry-id", entry.EntryID,
		"-witness-key-id", witKeyID,
		"-seed-file", witSeedFile,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("witness: %v\n%s", err, out)
	}

	// Re-fetch entry; it must now contain the cosignature.
	var fresh struct {
		WitnessCosignatures []struct {
			WitnessKeyID     string `json:"witness_key_id"`
			WitnessSignature string `json:"witness_signature"`
		} `json:"witness_cosignatures"`
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(out, &fresh); err != nil {
		t.Fatalf("decode cosign: %v\n%s", err, out)
	}
	if len(fresh.WitnessCosignatures) != 1 {
		t.Fatalf("expected 1 cosignature, got %d", len(fresh.WitnessCosignatures))
	}
	got := fresh.WitnessCosignatures[0]
	if got.WitnessKeyID != witKeyID {
		t.Fatalf("witness key mismatch: got %q", got.WitnessKeyID)
	}

	// Independently verify the witness signature against the canonical
	// report bytes the witness MUST have signed.
	var v any
	_ = json.Unmarshal(fresh.Report, &v)
	canon, _ := json.Marshal(v)
	sig, err := base64.StdEncoding.DecodeString(got.WitnessSignature)
	if err != nil {
		t.Fatalf("decode cosig: %v", err)
	}
	if !ed25519.Verify(witPub, canon, sig) {
		t.Fatal("witness signature failed external verification")
	}

	// Submitter signature still verifies via ctn-verify.
	trust := map[string]string{subKeyID: base64.StdEncoding.EncodeToString(subPub)}
	tb, _ := json.Marshal(trust)
	tf := filepath.Join(tmp, "trust.json")
	_ = os.WriteFile(tf, tb, 0o600)
	out, err = exec.Command(verifyBin,
		"-endpoint", srv.URL,
		"-entry-id", entry.EntryID,
		"-trust-file", tf,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Fatalf("expected OK from verify, got: %s", out)
	}

	_ = subPub
}
