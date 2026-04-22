package sigalg

import (
	"crypto/ed25519"
	"fmt"
)

var (
	ed25519Metadata = Spec{
		Algorithm:   Ed25519,
		PubKeySize:  ed25519.PublicKeySize,
		SigSize:     ed25519.SignatureSize,
		PostQuantum: false,
		Implemented: true,
	}
	mlDSA65Metadata = Spec{
		Algorithm:   MLDSA65,
		PubKeySize:  1952, // FIPS 204 §4 Table 2
		SigSize:     3309, // FIPS 204 §4 Table 2
		PostQuantum: true,
		Implemented: true, // placeholder implementation in mldsa.go
	}
	hybridMetadata = Spec{
		Algorithm:   HybridEd25519MLDSA65,
		PubKeySize:  4 + ed25519Metadata.PubKeySize + mlDSA65Metadata.PubKeySize,
		SigSize:     4 + ed25519Metadata.SigSize + mlDSA65Metadata.SigSize,
		PostQuantum: true,
		Implemented: true,
	}
)

// Lookup returns the Spec for an algorithm name, or ErrUnknown.
func Lookup(algorithm Algorithm) (Spec, error) {
	spec, ok := registeredSpec(algorithm)
	if !ok {
		return Spec{}, fmt.Errorf("%w: %q", ErrUnknown, algorithm)
	}
	return spec, nil
}

// All returns a stable list of registered algorithm names.
func All() []Algorithm {
	return []Algorithm{Ed25519, MLDSA65}
}

// ValidateSizes returns nil iff pub and sig have exactly the lengths
// required by the declared algorithm. Cheap, safe to call on untrusted
// input before invoking real crypto.
func ValidateSizes(algorithm Algorithm, publicKey, signature []byte) error {
	spec, err := Lookup(algorithm)
	if err != nil {
		return err
	}
	if len(publicKey) != spec.PubKeySize {
		return fmt.Errorf("%w: %s pubkey %d bytes, want %d",
			ErrSize, algorithm, len(publicKey), spec.PubKeySize)
	}
	if len(signature) != spec.SigSize {
		return fmt.Errorf("%w: %s signature %d bytes, want %d",
			ErrSize, algorithm, len(signature), spec.SigSize)
	}
	return nil
}

func registeredSpec(algorithm Algorithm) (Spec, bool) {
	switch algorithm {
	case Ed25519:
		return ed25519Metadata, true
	case MLDSA65:
		return mlDSA65Metadata, true
	case HybridEd25519MLDSA65:
		return hybridMetadata, true
	default:
		return Spec{}, false
	}
}

func mustRegisteredSpec(algorithm Algorithm) Spec {
	spec, _ := registeredSpec(algorithm)
	return spec
}
