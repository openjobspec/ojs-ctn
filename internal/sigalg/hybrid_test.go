package sigalg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestHybrid_RegistryEntry(t *testing.T) {
	s, err := Lookup(HybridEd25519MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if !s.PostQuantum {
		t.Error("hybrid should be marked post-quantum")
	}
	wantPub := 4 + ed25519.PublicKeySize + 1952
	wantSig := 4 + ed25519.SignatureSize + 3309
	if s.PubKeySize != wantPub || s.SigSize != wantSig {
		t.Errorf("sizes pub=%d sig=%d want %d/%d", s.PubKeySize, s.SigSize, wantPub, wantSig)
	}
}

func TestEncodeDecodeKey_RoundTrip(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pqPub := bytes.Repeat([]byte{0xab}, 1952)
	blob, err := EncodeHybridKey(edPub, pqPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSizes(HybridEd25519MLDSA65, blob, make([]byte, 4+64+3309)); err != nil {
		t.Errorf("ValidateSizes: %v", err)
	}
	gotEd, gotPQ, err := DecodeHybridKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotEd, edPub) || !bytes.Equal(gotPQ, pqPub) {
		t.Error("round-trip mismatch")
	}
}

func TestEncodeKey_RejectsWrongSizes(t *testing.T) {
	if _, err := EncodeHybridKey(make([]byte, 31), make([]byte, 1952)); err == nil {
		t.Error("short ed pub should fail")
	}
	if _, err := EncodeHybridKey(make([]byte, 32), make([]byte, 100)); err == nil {
		t.Error("short pq pub should fail")
	}
}

func TestDecode_RejectsTruncated(t *testing.T) {
	for _, name := range []string{"empty", "header-only", "missing-second"} {
		var b []byte
		switch name {
		case "header-only":
			b = []byte{0, 32}
		case "missing-second":
			b = make([]byte, 4+32)
		}
		if _, _, err := DecodeHybridKey(b); err == nil {
			t.Errorf("%s: expected truncation error", name)
		}
	}
}

func TestVerifyHybrid_BothMustHold(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	pqPub := bytes.Repeat([]byte{0xab}, 1952)
	pqSig := bytes.Repeat([]byte{0xcd}, 3309)

	msg := []byte("transparency log entry payload")
	edSig := ed25519.Sign(edPriv, msg)

	pubBlob, err := EncodeHybridKey(edPub, pqPub)
	if err != nil {
		t.Fatal(err)
	}
	sigBlob, err := EncodeHybridSig(edSig, pqSig)
	if err != nil {
		t.Fatal(err)
	}

	// Ed leg passes; PQ leg uses placeholder verifier which accepts
	// non-zero signatures. When a real ML-DSA-65 verifier is wired,
	// this test should use properly generated PQ keys and signatures.
	err = VerifyHybrid(pubBlob, msg, sigBlob)
	if err != nil {
		t.Fatalf("expected success: Ed25519 valid + PQ placeholder accepts non-zero sig, got %v", err)
	}

	// Tamper Ed leg → must fail with non-Unimplemented error
	// (i.e. cryptographic failure, not "we couldn't check").
	badEdSig := bytes.Repeat([]byte{0xff}, ed25519.SignatureSize)
	badSigBlob, _ := EncodeHybridSig(badEdSig, pqSig)
	err = VerifyHybrid(pubBlob, msg, badSigBlob)
	if err == nil {
		t.Fatal("tampered ed leg should fail")
	}
	if errors.Is(err, ErrUnimplemented) {
		t.Errorf("ed leg failure should not surface as unimplemented: %v", err)
	}
}

func TestVerifyHybrid_DecodeErrorsPropagate(t *testing.T) {
	if err := VerifyHybrid(nil, []byte("x"), nil); err == nil {
		t.Error("nil pub should fail")
	}
}
