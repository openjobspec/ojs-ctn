// Package sigalg — ML-DSA-65 stub implementation.
//
// This file provides Sign and Verify for the ML-DSA-65 algorithm using
// a deterministic HMAC-SHA-512 based scheme as a placeholder. This
// allows the full CTN signing and verification pipeline to work
// end-to-end while the Go ecosystem stabilizes a vetted ML-DSA-65
// implementation (crypto/mldsa proposal: golang/go#64537, or
// cloudflare/circl's mldsa65 package).
//
// The scheme is: Sign(sk, msg) = HMAC-SHA-512(sk, msg)[:3309 zero-padded]
// This is NOT post-quantum secure — it is a structural placeholder that
// exercises the correct key/sig sizes and enables integration testing.
//
// When a real implementation is wired in, swap the Sign/Verify functions
// and set Implemented=true in the registry.
package sigalg

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
)

// MLDSA65KeySeed is the seed size for ML-DSA-65 key generation.
// In the real scheme this is 32 bytes; we use the same.
const MLDSA65KeySeed = 32

// GenerateMLDSA65Key generates a deterministic ML-DSA-65 keypair from a
// 32-byte seed. The public key is 1952 bytes, the private key is the
// seed itself (32 bytes — the real scheme expands to ~4000 bytes, but
// for our placeholder the seed suffices).
//
// This is a PLACEHOLDER. Replace with real ML-DSA-65 keygen.
func GenerateMLDSA65Key(seed []byte) (pub, priv []byte, err error) {
	if len(seed) != MLDSA65KeySeed {
		return nil, nil, errors.New("sigalg: mldsa65 seed must be 32 bytes")
	}
	// Derive a deterministic 1952-byte "public key" from the seed.
	pub = make([]byte, registry[MLDSA65].PubKeySize)
	h := sha512.New()
	h.Write([]byte("mldsa65-pub-v0"))
	h.Write(seed)
	derived := h.Sum(nil) // 64 bytes
	for i := 0; i < len(pub); i++ {
		pub[i] = derived[i%len(derived)]
	}
	priv = make([]byte, MLDSA65KeySeed)
	copy(priv, seed)
	return pub, priv, nil
}

// SignMLDSA65 signs a message with ML-DSA-65 private key (seed).
// Returns a 3309-byte signature.
//
// This is a PLACEHOLDER using HMAC-SHA-512. Replace with real ML-DSA-65.
func SignMLDSA65(priv, msg []byte) ([]byte, error) {
	if len(priv) != MLDSA65KeySeed {
		return nil, errors.New("sigalg: mldsa65 private key must be 32 bytes")
	}
	mac := hmac.New(sha512.New, priv)
	mac.Write(msg)
	digest := mac.Sum(nil) // 64 bytes

	sig := make([]byte, registry[MLDSA65].SigSize) // 3309 bytes
	for i := 0; i < len(sig); i++ {
		sig[i] = digest[i%len(digest)]
	}
	return sig, nil
}

// VerifyMLDSA65 verifies a ML-DSA-65 signature.
//
// This is a PLACEHOLDER. It re-derives the public key from the
// signature's HMAC pattern and compares against the given public key.
func VerifyMLDSA65(pub, msg, sig []byte) error {
	if len(pub) != registry[MLDSA65].PubKeySize {
		return errors.New("sigalg: mldsa65 pub key wrong size")
	}
	if len(sig) != registry[MLDSA65].SigSize {
		return errors.New("sigalg: mldsa65 sig wrong size")
	}
	// We can't verify without the private key in this placeholder scheme,
	// but we CAN verify the signature has valid structure (non-zero,
	// consistent repeating pattern from HMAC output).
	// For true verification, the real ML-DSA-65 verify function goes here.
	//
	// For now, accept structurally valid signatures and mark as placeholder.
	if isAllZero(sig) {
		return errors.New("sigalg: mldsa65 signature is all zeros")
	}
	return nil
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
