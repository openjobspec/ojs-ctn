package attestlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleEvidence() Evidence {
	hsh := sha256.Sum256([]byte("input"))
	return Evidence{
		Version:     1,
		Algorithm:   "ed25519",
		Type:        "signature-only",
		KeyID:       "key-1",
		InputDigest: hex.EncodeToString(hsh[:]),
		Signature:   "AAAA",
		SignedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

func TestToSubmission_Roundtrip(t *testing.T) {
	e := sampleEvidence()
	sub, err := ToSubmission(e)
	if err != nil {
		t.Fatal(err)
	}
	if sub.SubmitterKeyID != e.KeyID {
		t.Errorf("key id mismatch: %s vs %s", sub.SubmitterKeyID, e.KeyID)
	}
	if sub.SubmitterSignature != e.Signature {
		t.Errorf("sig mismatch")
	}
	var report Report
	if err := json.Unmarshal(sub.Report, &report); err != nil {
		t.Fatal(err)
	}
	if report.InputDigest != e.InputDigest || report.Algorithm != e.Algorithm {
		t.Errorf("report fields not preserved: %+v", report)
	}
}

func TestReportHash_Stable(t *testing.T) {
	e := sampleEvidence()
	h1, err := ReportHash(e)
	if err != nil {
		t.Fatal(err)
	}
	// Re-marshalling shouldn't change the hash; canonical Go encoding
	// is field-declaration order, which we froze in Report.
	h2, _ := ReportHash(e)
	if h1 != h2 {
		t.Errorf("hash unstable: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("hash length=%d want 64", len(h1))
	}
}

func TestReportHash_SignatureChangeDoesNotAffect(t *testing.T) {
	e := sampleEvidence()
	h1, _ := ReportHash(e)
	e.Signature = "ZZZZ"
	h2, _ := ReportHash(e)
	if h1 != h2 {
		t.Errorf("changing signature must NOT change report hash (sig is not part of attested computation)")
	}
}

func TestReportHash_OutputDigestAffects(t *testing.T) {
	e := sampleEvidence()
	h1, _ := ReportHash(e)
	out := sha256.Sum256([]byte("out"))
	e.OutputDigest = hex.EncodeToString(out[:])
	h2, _ := ReportHash(e)
	if h1 == h2 {
		t.Errorf("changing output_digest MUST change report hash")
	}
}

func TestValidate_Errors(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Evidence)
		want  string
	}{
		{"bad version", func(e *Evidence) { e.Version = 2 }, "unsupported"},
		{"unknown alg", func(e *Evidence) { e.Algorithm = "rsa-2048" }, "unknown"},
		{"unknown type", func(e *Evidence) { e.Type = "magic-tee" }, "unknown evidence type"},
		{"empty key id", func(e *Evidence) { e.KeyID = "" }, "key_id required"},
		{"empty sig", func(e *Evidence) { e.Signature = "" }, "signature required"},
		{"missing input digest", func(e *Evidence) { e.InputDigest = "" }, "required"},
		{"short input digest", func(e *Evidence) { e.InputDigest = "abcd" }, "must be 32-byte"},
		{"non-hex input digest", func(e *Evidence) { e.InputDigest = strings.Repeat("Z", 64) }, "not hex"},
		{"bad output digest", func(e *Evidence) { e.OutputDigest = "abcd" }, "output_digest"},
		{"bad signed_at", func(e *Evidence) { e.SignedAt = "yesterday" }, "signed_at"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := sampleEvidence()
			c.mut(&e)
			err := e.Validate()
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err=%v want substr %q", err, c.want)
			}
		})
	}
}

func TestValidate_AcceptsHybridAlg(t *testing.T) {
	e := sampleEvidence()
	e.Algorithm = "ml-dsa-65"
	if err := e.Validate(); err != nil {
		t.Errorf("ml-dsa-65 should be a registered alg: %v", err)
	}
}
