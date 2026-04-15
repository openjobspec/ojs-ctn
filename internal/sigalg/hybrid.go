package sigalg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HybridEd25519MLDSA65 is the canonical name of the hybrid scheme:
// concatenated Ed25519 and ML-DSA-65 signatures (and public keys),
// with both required to verify. This is the M5/P3 default once
// post-quantum support ships, providing forward compatibility (an
// attacker who breaks one scheme alone cannot forge a hybrid sig).
//
// Wire layout for keys and signatures uses a 2-byte big-endian
// length prefix on each component:
//
//   pubkey = u16 len_ed | ed25519_pub (32) | u16 len_pq | mldsa_pub (1952)
//   sig    = u16 len_ed | ed25519_sig (64) | u16 len_pq | mldsa_sig (3309)
//
// Length-prefixing (rather than fixed offsets) keeps the format
// extensible if either component's size changes in a future revision
// of FIPS 204 or in a new sigalg revision (e.g. Dilithium2/5).
const HybridEd25519MLDSA65 Algorithm = "hybrid-ed25519-ml-dsa-65"

func init() {
	specEd := registry[Ed25519]
	specPQ := registry[MLDSA65]
	registry[HybridEd25519MLDSA65] = Spec{
		Algorithm:   HybridEd25519MLDSA65,
		PubKeySize:  4 + specEd.PubKeySize + specPQ.PubKeySize,
		SigSize:     4 + specEd.SigSize + specPQ.SigSize,
		PostQuantum: true,
		// Marked Implemented=true now that ML-DSA placeholder is wired.
		Implemented: true,
	}
}

// EncodeHybridKey produces the wire form of a hybrid public key from
// its two constituent components.
func EncodeHybridKey(edPub, pqPub []byte) ([]byte, error) {
	if len(edPub) != registry[Ed25519].PubKeySize {
		return nil, fmt.Errorf("%w: ed25519 pub %d, want %d",
			ErrSize, len(edPub), registry[Ed25519].PubKeySize)
	}
	if len(pqPub) != registry[MLDSA65].PubKeySize {
		return nil, fmt.Errorf("%w: ml-dsa-65 pub %d, want %d",
			ErrSize, len(pqPub), registry[MLDSA65].PubKeySize)
	}
	return encodeTwoComponents(edPub, pqPub), nil
}

// EncodeHybridSig produces the wire form of a hybrid signature.
func EncodeHybridSig(edSig, pqSig []byte) ([]byte, error) {
	if len(edSig) != registry[Ed25519].SigSize {
		return nil, fmt.Errorf("%w: ed25519 sig %d, want %d",
			ErrSize, len(edSig), registry[Ed25519].SigSize)
	}
	if len(pqSig) != registry[MLDSA65].SigSize {
		return nil, fmt.Errorf("%w: ml-dsa-65 sig %d, want %d",
			ErrSize, len(pqSig), registry[MLDSA65].SigSize)
	}
	return encodeTwoComponents(edSig, pqSig), nil
}

// DecodeHybridKey splits a hybrid key blob into its two halves.
func DecodeHybridKey(b []byte) (edPub, pqPub []byte, err error) {
	return decodeTwoComponents(b)
}

// DecodeHybridSig splits a hybrid signature blob into its two halves.
func DecodeHybridSig(b []byte) (edSig, pqSig []byte, err error) {
	return decodeTwoComponents(b)
}

// VerifyHybrid verifies that a hybrid signature is valid: BOTH
// component verifications must succeed. Returns ErrUnimplemented if
// the post-quantum component cannot yet be checked locally — callers
// that want degraded mode (verify Ed25519 only and continue) should
// inspect the error and decide; CTN's strict mode treats it as a hard
// failure.
func VerifyHybrid(pub, msg, sig []byte) error {
	edPub, pqPub, err := DecodeHybridKey(pub)
	if err != nil {
		return fmt.Errorf("hybrid pub: %w", err)
	}
	edSig, pqSig, err := DecodeHybridSig(sig)
	if err != nil {
		return fmt.Errorf("hybrid sig: %w", err)
	}
	if err := Verify(Ed25519, edPub, msg, edSig); err != nil {
		return fmt.Errorf("hybrid: ed25519 leg: %w", err)
	}
	if err := Verify(MLDSA65, pqPub, msg, pqSig); err != nil {
		// Bubble Unimplemented up so callers can choose policy.
		return fmt.Errorf("hybrid: ml-dsa-65 leg: %w", err)
	}
	return nil
}

func encodeTwoComponents(a, b []byte) []byte {
	out := make([]byte, 4+len(a)+len(b))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(a)))
	copy(out[2:2+len(a)], a)
	binary.BigEndian.PutUint16(out[2+len(a):4+len(a)], uint16(len(b)))
	copy(out[4+len(a):], b)
	return out
}

func decodeTwoComponents(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("sigalg: hybrid blob truncated (header)")
	}
	la := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < 2+la+2 {
		return nil, nil, errors.New("sigalg: hybrid blob truncated (component A)")
	}
	a := b[2 : 2+la]
	lb := int(binary.BigEndian.Uint16(b[2+la : 4+la]))
	if len(b) != 4+la+lb {
		return nil, nil, fmt.Errorf("sigalg: hybrid blob length %d, expected %d",
			len(b), 4+la+lb)
	}
	bb := b[4+la:]
	return a, bb, nil
}
