package sigalg

import (
	"bytes"
	"testing"
)

func TestGenerateMLDSA65Key(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	pub, priv, err := GenerateMLDSA65Key(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 1952 {
		t.Errorf("pub key size = %d, want 1952", len(pub))
	}
	if len(priv) != 32 {
		t.Errorf("priv key size = %d, want 32", len(priv))
	}

	// Deterministic: same seed → same key
	pub2, _, err := GenerateMLDSA65Key(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, pub2) {
		t.Error("same seed should produce same public key")
	}
}

func TestGenerateMLDSA65Key_BadSeed(t *testing.T) {
	_, _, err := GenerateMLDSA65Key(make([]byte, 16))
	if err == nil {
		t.Error("expected error for wrong seed size")
	}
}

func TestSignVerifyMLDSA65(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 42)
	}

	pub, priv, err := GenerateMLDSA65Key(seed)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message for ML-DSA-65")
	sig, err := SignMLDSA65(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 3309 {
		t.Errorf("sig size = %d, want 3309", len(sig))
	}

	// Verify should succeed
	if err := VerifyMLDSA65(pub, msg, sig); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestSignMLDSA65_Deterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	_, priv, _ := GenerateMLDSA65Key(seed)
	msg := []byte("determinism test")

	sig1, _ := SignMLDSA65(priv, msg)
	sig2, _ := SignMLDSA65(priv, msg)

	if !bytes.Equal(sig1, sig2) {
		t.Error("same key+msg should produce same signature")
	}
}

func TestVerifyMLDSA65_ZeroSig(t *testing.T) {
	seed := make([]byte, 32)
	pub, _, _ := GenerateMLDSA65Key(seed)

	zeroSig := make([]byte, 3309)
	if err := VerifyMLDSA65(pub, []byte("msg"), zeroSig); err == nil {
		t.Error("should reject all-zero signature")
	}
}

func TestVerifyMLDSA65_WrongSize(t *testing.T) {
	if err := VerifyMLDSA65(make([]byte, 10), []byte("msg"), make([]byte, 10)); err == nil {
		t.Error("should reject wrong size")
	}
}

func TestMLDSA65ViaRegistry(t *testing.T) {
	spec, err := Lookup(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Implemented {
		t.Error("ML-DSA-65 should be marked as implemented")
	}
	if !spec.PostQuantum {
		t.Error("ML-DSA-65 should be marked as post-quantum")
	}
}

func TestMLDSA65VerifyViaRegistry(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 7)
	}

	pub, priv, _ := GenerateMLDSA65Key(seed)
	msg := []byte("registry verify test")
	sig, _ := SignMLDSA65(priv, msg)

	// Verify via the registry dispatch (Verify function in sigalg.go)
	if err := Verify(MLDSA65, pub, msg, sig); err != nil {
		t.Errorf("Verify(MLDSA65) failed: %v", err)
	}
}
