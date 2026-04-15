package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mkEntry(t *testing.T, seq uint64, witnesses int, pk ed25519.PublicKey, sk ed25519.PrivateKey, badSig bool) entry {
	t.Helper()
	rep := json.RawMessage(fmt.Sprintf(`{"job":"j-%d"}`, seq))
	canonical, _ := canonicalize(rep)
	sum := sha256.Sum256(canonical)
	sig := ed25519.Sign(sk, canonical)
	if badSig {
		sig[0] ^= 0xff
	}
	cosigns := []witnessCosignature{}
	for i := 0; i < witnesses; i++ {
		cosigns = append(cosigns, witnessCosignature{WitnessKeyID: fmt.Sprintf("w%d", i), CosignedAt: time.Now().UTC()})
	}
	return entry{
		EntryID:             fmt.Sprintf("e-%d", seq),
		LoggedAt:            time.Unix(int64(1000+seq), 0).UTC(),
		ReportSHA256:        hexEncode(sum[:]),
		Report:              rep,
		SubmitterSignature:  base64.StdEncoding.EncodeToString(sig),
		SubmitterKeyID:      "k1",
		SequenceNumber:      seq,
		WitnessCosignatures: cosigns,
	}
}

func TestAnalyse_HealthyAndCoverage(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]ed25519.PublicKey{"k1": pk}
	entries := []entry{
		mkEntry(t, 5, 2, pk, sk, false),
		mkEntry(t, 4, 1, pk, sk, false),
		mkEntry(t, 3, 0, pk, sk, false),
	}
	r := analyse("ep", head{Size: 5}, entries, trust, 0.5)
	if r.EntriesAudited != 3 {
		t.Errorf("audited=%d", r.EntriesAudited)
	}
	if r.Verification.SignedOK != 3 {
		t.Errorf("signed_ok=%d want 3", r.Verification.SignedOK)
	}
	if r.WitnessCoverage.AtLeast1 != 2 || r.WitnessCoverage.AtLeast2 != 1 {
		t.Errorf("witness counts: %+v", r.WitnessCoverage)
	}
	if r.WitnessCoverage.Coverage1Pct < 0.66 || r.WitnessCoverage.Coverage1Pct > 0.67 {
		t.Errorf("coverage pct=%v", r.WitnessCoverage.Coverage1Pct)
	}
	if !r.Healthy {
		t.Errorf("should be healthy: %+v", r)
	}
}

func TestAnalyse_BadSigDetected(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]ed25519.PublicKey{"k1": pk}
	entries := []entry{
		mkEntry(t, 1, 1, pk, sk, false),
		mkEntry(t, 2, 1, pk, sk, true),
	}
	r := analyse("ep", head{Size: 2}, entries, trust, 0)
	if r.Verification.BadSig != 1 {
		t.Errorf("bad_sig=%d want 1", r.Verification.BadSig)
	}
	if r.Healthy {
		t.Error("must be unhealthy with bad sig")
	}
	if len(r.Failures) != 1 || r.Failures[0].EntryID != "e-2" {
		t.Errorf("failures=%v", r.Failures)
	}
}

func TestAnalyse_UnknownKey(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	otherTrust := map[string]ed25519.PublicKey{"different-key": pk}
	r := analyse("ep", head{Size: 1}, []entry{mkEntry(t, 1, 0, pk, sk, false)}, otherTrust, 0)
	if r.Verification.UnknownKey != 1 {
		t.Errorf("unknown_key=%d want 1", r.Verification.UnknownKey)
	}
}

func TestAnalyse_SkippedWhenNoTrust(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	r := analyse("ep", head{Size: 1}, []entry{mkEntry(t, 1, 0, pk, sk, false)}, nil, 0)
	if r.Verification.Skipped != 1 {
		t.Errorf("skipped=%d", r.Verification.Skipped)
	}
}

func TestAnalyse_SeqGaps(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	entries := []entry{mkEntry(t, 5, 0, pk, sk, false), mkEntry(t, 3, 0, pk, sk, false), mkEntry(t, 1, 0, pk, sk, false)}
	r := analyse("ep", head{Size: 5}, entries, nil, 0)
	want := map[uint64]bool{2: true, 4: true}
	if len(r.SeqGaps) != 2 {
		t.Fatalf("gaps=%v want 2", r.SeqGaps)
	}
	for _, g := range r.SeqGaps {
		if !want[g] {
			t.Errorf("unexpected gap: %d", g)
		}
	}
}

func TestAnalyse_BelowCoverageUnhealthy(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	r := analyse("ep", head{Size: 2}, []entry{mkEntry(t, 1, 0, pk, sk, false), mkEntry(t, 2, 0, pk, sk, false)}, map[string]ed25519.PublicKey{"k1": pk}, 0.5)
	if r.Healthy {
		t.Error("0%% coverage must be unhealthy at 50%% required")
	}
}

func TestFetchTail_Skips404(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/entries/seq:") {
			http.NotFound(w, r)
			return
		}
		seq := r.URL.Path[len("/v1/entries/seq:"):]
		// only seq:2 exists; seq:1 returns 404
		if seq != "2" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(mkEntry(t, 2, 0, pk, sk, false))
	}))
	defer srv.Close()
	out, err := fetchTail(context.Background(), srv.Client(), srv.URL, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].SequenceNumber != 2 {
		t.Errorf("expected only seq 2, got %v", out)
	}
}
