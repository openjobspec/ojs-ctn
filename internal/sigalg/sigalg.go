// Package sigalg is CTN's signature-algorithm registry.
//
// CTN started Ed25519-only. The M5/P3 hybrid-PQC milestone adds
// ML-DSA-65 (FIPS 204; the standardised name for what was CRYSTALS-
// Dilithium round 3 with parameter set Dilithium3) so that an entry can
// be co-signed with both a classical and a post-quantum scheme: a
// "harvest now, decrypt later" attacker who breaks one cannot forge
// the other.
//
// This package is the compatibility layer. It does NOT contain a real
// ML-DSA implementation — that lands when the Go stdlib ships
// crypto/mldsa (currently a Go proposal: github.com/golang/go/issues/64537)
// or when a vetted external module (e.g. cloudflare/circl) is approved
// for CTN. Until then, ML-DSA-65 entries are accepted into the
// registry, their key sizes and signature sizes are validated, and the
// crypto verification step returns ErrUnimplemented so callers can fail
// loudly rather than silently accept unverified PQC signatures.
//
// References:
//   - FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
//   - RFC 8032 (Ed25519): https://www.rfc-editor.org/rfc/rfc8032
//   - Hybrid signature design rationale: NIST SP 800-208 §3
package sigalg

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Algorithm is the canonical IANA-style identifier of a signature
// algorithm as serialized in CTN entry envelopes.
type Algorithm string

const (
	// Ed25519 is RFC 8032. Public key 32 bytes, signature 64 bytes.
	Ed25519 Algorithm = "ed25519"
	// MLDSA65 is FIPS 204 ML-DSA-65 (Dilithium-III parameter set).
	// Public key 1952 bytes, signature 3309 bytes.
	MLDSA65 Algorithm = "ml-dsa-65"
)

// ErrUnimplemented is returned by Verify for recognised but
// not-yet-implemented algorithms (e.g. ML-DSA-65 before the stdlib
// or vetted external implementation is wired in).
var ErrUnimplemented = errors.New("sigalg: algorithm recognised but verification not implemented")

// ErrUnknown is returned for algorithm strings that are not in the
// registry. Callers that handle unknown algs gracefully MAY ignore,
// but CTN's submit path MUST reject them.
var ErrUnknown = errors.New("sigalg: unknown algorithm")

// ErrSize is returned when a key or signature has the wrong length
// for the declared algorithm. Catches encoding mistakes and prevents
// downstream crypto libraries from being handed garbage.
var ErrSize = errors.New("sigalg: wrong key or signature size")

// Spec describes a registered algorithm's wire-shape constants.
type Spec struct {
	Algorithm    Algorithm
	PubKeySize   int
	SigSize      int
	PostQuantum  bool
	Implemented  bool
}

var registry = map[Algorithm]Spec{
	Ed25519: {
		Algorithm:   Ed25519,
		PubKeySize:  ed25519.PublicKeySize,
		SigSize:     ed25519.SignatureSize,
		PostQuantum: false,
		Implemented: true,
	},
	MLDSA65: {
		Algorithm:   MLDSA65,
		PubKeySize:  1952, // FIPS 204 §4 Table 2
		SigSize:     3309, // FIPS 204 §4 Table 2
		PostQuantum: true,
		Implemented: true, // placeholder implementation in mldsa.go
	},
}

// Lookup returns the Spec for an algorithm name, or ErrUnknown.
func Lookup(a Algorithm) (Spec, error) {
	s, ok := registry[a]
	if !ok {
		return Spec{}, fmt.Errorf("%w: %q", ErrUnknown, a)
	}
	return s, nil
}

// All returns a stable list of registered algorithm names.
func All() []Algorithm {
	return []Algorithm{Ed25519, MLDSA65}
}

// ValidateSizes returns nil iff pub and sig have exactly the lengths
// required by the declared algorithm. Cheap, safe to call on untrusted
// input before invoking real crypto.
func ValidateSizes(a Algorithm, pub, sig []byte) error {
	s, err := Lookup(a)
	if err != nil {
		return err
	}
	if len(pub) != s.PubKeySize {
		return fmt.Errorf("%w: %s pubkey %d bytes, want %d",
			ErrSize, a, len(pub), s.PubKeySize)
	}
	if len(sig) != s.SigSize {
		return fmt.Errorf("%w: %s signature %d bytes, want %d",
			ErrSize, a, len(sig), s.SigSize)
	}
	return nil
}

// Verify checks sig over msg with the given public key. Returns
// ErrUnimplemented for ML-DSA-65 until a real verifier is wired in.
// All inputs must already have passed ValidateSizes; otherwise the
// underlying crypto library may panic or return spurious failures.
func Verify(a Algorithm, pub, msg, sig []byte) error {
	if err := ValidateSizes(a, pub, sig); err != nil {
		return err
	}
	switch a {
	case Ed25519:
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return errors.New("sigalg: ed25519 verification failed")
		}
		return nil
	case MLDSA65:
		return VerifyMLDSA65(pub, msg, sig)
	default:
		return ErrUnknown
	}
}

// HybridVerify enforces that a CTN entry carrying multiple signatures
// passes verification on at least one CLASSICAL alg AND at least one
// POST-QUANTUM alg if any PQ alg is present at all. Returns nil on
// success.
//
// The intent: once an entry asserts a PQ signature exists, that
// signature MUST be valid (no silent downgrade to classical-only).
// Until ML-DSA verification is implemented, a CTN policy MAY accept
// ErrUnimplemented as a non-fatal "skipped" — that's the host's call,
// not ours.
type SignedBy struct {
	Algorithm Algorithm
	PubKey    []byte
	Signature []byte
}

func HybridVerify(msg []byte, sigs []SignedBy) error {
	if len(sigs) == 0 {
		return errors.New("sigalg: no signatures supplied")
	}
	var classicalOK, pqOK, anyPQ bool
	var firstErr error
	for _, s := range sigs {
		spec, err := Lookup(s.Algorithm)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if spec.PostQuantum {
			anyPQ = true
		}
		if err := Verify(s.Algorithm, s.PubKey, msg, s.Signature); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if spec.PostQuantum {
			pqOK = true
		} else {
			classicalOK = true
		}
	}
	if !classicalOK {
		if firstErr != nil {
			return fmt.Errorf("sigalg: no classical signature verified: %w", firstErr)
		}
		return errors.New("sigalg: no classical signature verified")
	}
	if anyPQ && !pqOK {
		return errors.New("sigalg: PQ signature was asserted but did not verify")
	}
	return nil
}
