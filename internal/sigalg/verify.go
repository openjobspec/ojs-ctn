package sigalg

import (
	"crypto/ed25519"
	"errors"
)

// Verify checks sig over msg with the given public key. Returns
// ErrUnimplemented for ML-DSA-65 until a real verifier is wired in.
// All inputs must already have passed ValidateSizes; otherwise the
// underlying crypto library may panic or return spurious failures.
func Verify(algorithm Algorithm, publicKey, message, signature []byte) error {
	if err := ValidateSizes(algorithm, publicKey, signature); err != nil {
		return err
	}
	switch algorithm {
	case Ed25519:
		if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
			return errors.New("sigalg: ed25519 verification failed")
		}
		return nil
	case MLDSA65:
		return VerifyMLDSA65(publicKey, message, signature)
	default:
		return ErrUnknown
	}
}
