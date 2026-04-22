package sigalg

import (
	"errors"
	"fmt"
)

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

func HybridVerify(message []byte, signatures []SignedBy) error {
	if len(signatures) == 0 {
		return errors.New("sigalg: no signatures supplied")
	}
	var classicalOK, pqOK, anyPQ bool
	var firstErr error
	for _, signature := range signatures {
		spec, err := Lookup(signature.Algorithm)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if spec.PostQuantum {
			anyPQ = true
		}
		if err := Verify(signature.Algorithm, signature.PubKey, message, signature.Signature); err != nil {
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
