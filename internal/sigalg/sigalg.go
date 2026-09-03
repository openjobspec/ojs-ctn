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
	"errors"
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
	Algorithm   Algorithm
	PubKeySize  int
	SigSize     int
	PostQuantum bool
	Implemented bool
}
