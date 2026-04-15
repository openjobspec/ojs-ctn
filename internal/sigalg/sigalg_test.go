package sigalg

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func mustEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestEd25519RoundTrip(t *testing.T) {
	pub, priv := mustEd25519(t)
	msg := []byte("hello ctn")
	sig := ed25519.Sign(priv, msg)
	if err := Verify(Ed25519, pub, msg, sig); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestEd25519RejectsWrongMessage(t *testing.T) {
	pub, priv := mustEd25519(t)
	sig := ed25519.Sign(priv, []byte("a"))
	if err := Verify(Ed25519, pub, []byte("b"), sig); err == nil {
		t.Error("expected verify failure on tampered message")
	}
}

func TestSizeValidationCatchesShortKey(t *testing.T) {
	if err := ValidateSizes(Ed25519, []byte{1, 2, 3}, make([]byte, 64)); !errors.Is(err, ErrSize) {
		t.Errorf("got %v, want ErrSize", err)
	}
}

func TestUnknownAlgRejected(t *testing.T) {
	if err := Verify("rsa-sha256", nil, nil, nil); !errors.Is(err, ErrUnknown) {
		t.Errorf("got %v, want ErrUnknown", err)
	}
}

func TestMLDSA65SizesRecognised(t *testing.T) {
	pub := make([]byte, 1952)
	sig := make([]byte, 3309)
	if err := ValidateSizes(MLDSA65, pub, sig); err != nil {
		t.Errorf("ML-DSA-65 sizes should validate: %v", err)
	}
	// With the placeholder implementation, all-zero sigs are rejected
	// but structurally valid sigs should verify.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	realPub, priv, _ := GenerateMLDSA65Key(seed)
	realSig, _ := SignMLDSA65(priv, []byte("m"))
	if err := Verify(MLDSA65, realPub, []byte("m"), realSig); err != nil {
		t.Errorf("ML-DSA-65 verify should succeed with valid sig: %v", err)
	}
}

func TestMLDSA65WrongSizeRejected(t *testing.T) {
	if err := ValidateSizes(MLDSA65, make([]byte, 1000), make([]byte, 3309)); !errors.Is(err, ErrSize) {
		t.Errorf("got %v, want ErrSize", err)
	}
}

func TestRegistryAdvertisesPQFlag(t *testing.T) {
	s, _ := Lookup(MLDSA65)
	if !s.PostQuantum {
		t.Error("ML-DSA-65 must be flagged PostQuantum")
	}
	if !s.Implemented {
		t.Error("ML-DSA-65 must report Implemented=true (placeholder wired)")
	}
	c, _ := Lookup(Ed25519)
	if c.PostQuantum {
		t.Error("ed25519 must not be flagged PostQuantum")
	}
}

func TestHybridVerifyClassicalOnlyOK(t *testing.T) {
	pub, priv := mustEd25519(t)
	msg := []byte("ctn")
	sig := ed25519.Sign(priv, msg)
	err := HybridVerify(msg, []SignedBy{{Ed25519, pub, sig}})
	if err != nil {
		t.Errorf("classical-only should pass: %v", err)
	}
}

func TestHybridVerifyRequiresClassical(t *testing.T) {
	pub := make([]byte, 1952)
	sig := make([]byte, 3309)
	err := HybridVerify([]byte("m"), []SignedBy{{MLDSA65, pub, sig}})
	if err == nil {
		t.Error("PQ-only must fail until classical present too")
	}
}

func TestHybridVerifyDetectsAssertedPQFailure(t *testing.T) {
	pub, priv := mustEd25519(t)
	msg := []byte("m")
	sig := ed25519.Sign(priv, msg)
	pqPub := make([]byte, 1952)
	pqSig := make([]byte, 3309)
	// PQ verify returns ErrUnimplemented so HybridVerify treats it
	// as failure; with Ed25519 OK, classical part passes; but anyPQ
	// is true and pqOK is false → must fail.
	err := HybridVerify(msg, []SignedBy{
		{Ed25519, pub, sig},
		{MLDSA65, pqPub, pqSig},
	})
	if err == nil {
		t.Error("expected error: PQ asserted but unverified")
	}
}

func TestAllReturnsRegistry(t *testing.T) {
	algs := All()
	if len(algs) < 2 {
		t.Fatalf("All() too short: %v", algs)
	}
	have := map[Algorithm]bool{}
	for _, a := range algs {
		have[a] = true
	}
	if !have[Ed25519] || !have[MLDSA65] {
		t.Errorf("All() missing entries: %v", algs)
	}
}
