package sigalg

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
)

func TestRegistryMetadataAndErrorsCharacterization(t *testing.T) {
	if got := All(); !reflect.DeepEqual(got, []Algorithm{Ed25519, MLDSA65}) {
		t.Fatalf("All = %v", got)
	}
	tests := []struct {
		algorithm Algorithm
		want      Spec
	}{
		{
			algorithm: Ed25519,
			want: Spec{
				Algorithm: Ed25519, PubKeySize: 32, SigSize: 64,
				PostQuantum: false, Implemented: true,
			},
		},
		{
			algorithm: MLDSA65,
			want: Spec{
				Algorithm: MLDSA65, PubKeySize: 1952, SigSize: 3309,
				PostQuantum: true, Implemented: true,
			},
		},
		{
			algorithm: HybridEd25519MLDSA65,
			want: Spec{
				Algorithm: HybridEd25519MLDSA65, PubKeySize: 1988, SigSize: 3377,
				PostQuantum: true, Implemented: true,
			},
		},
	}
	for _, tt := range tests {
		got, err := Lookup(tt.algorithm)
		if err != nil || got != tt.want {
			t.Fatalf("Lookup(%q) = %+v, %v; want %+v", tt.algorithm, got, err, tt.want)
		}
	}
	if _, err := Lookup("rsa"); err == nil || err.Error() != `sigalg: unknown algorithm: "rsa"` ||
		!errors.Is(err, ErrUnknown) {
		t.Fatalf("Lookup unknown error = %v", err)
	}
}

func TestValidateSizesErrorOrderAndText(t *testing.T) {
	tests := []struct {
		name      string
		algorithm Algorithm
		pub       []byte
		sig       []byte
		want      string
	}{
		{name: "unknown first", algorithm: "rsa", want: `sigalg: unknown algorithm: "rsa"`},
		{
			name: "public key before signature", algorithm: Ed25519,
			pub: make([]byte, 31), sig: make([]byte, 63),
			want: "sigalg: wrong key or signature size: ed25519 pubkey 31 bytes, want 32",
		},
		{
			name: "signature second", algorithm: Ed25519,
			pub: make([]byte, 32), sig: make([]byte, 63),
			want: "sigalg: wrong key or signature size: ed25519 signature 63 bytes, want 64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSizes(tt.algorithm, tt.pub, tt.sig)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("ValidateSizes error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestVerifyDispatchCharacterization(t *testing.T) {
	validHybridPub := make([]byte, 1988)
	validHybridSig := make([]byte, 3377)
	if err := Verify(HybridEd25519MLDSA65, validHybridPub, nil, validHybridSig); err != ErrUnknown {
		t.Fatalf("Verify(hybrid) error = %v, want bare ErrUnknown", err)
	}
	if err := Verify("rsa", nil, nil, nil); err == nil ||
		err.Error() != `sigalg: unknown algorithm: "rsa"` {
		t.Fatalf("Verify(unknown) error = %v", err)
	}
}

func TestHybridAcceptancePolicyCharacterization(t *testing.T) {
	message := []byte("message")
	edPublic, edPrivate := mustEd25519(t)
	validEd := SignedBy{
		Algorithm: Ed25519,
		PubKey:    edPublic,
		Signature: ed25519.Sign(edPrivate, message),
	}
	invalidEd := SignedBy{
		Algorithm: Ed25519,
		PubKey:    edPublic,
		Signature: bytes.Repeat([]byte{0xff}, ed25519.SignatureSize),
	}
	validPQ := SignedBy{
		Algorithm: MLDSA65,
		PubKey:    bytes.Repeat([]byte{0xaa}, 1952),
		Signature: bytes.Repeat([]byte{0xbb}, 3309),
	}
	invalidPQ := SignedBy{
		Algorithm: MLDSA65,
		PubKey:    make([]byte, 1952),
		Signature: make([]byte, 3309),
	}
	unknown := SignedBy{Algorithm: "rsa"}

	tests := []struct {
		name       string
		signatures []SignedBy
		want       string
	}{
		{name: "none", want: "sigalg: no signatures supplied"},
		{
			name: "unknown only", signatures: []SignedBy{unknown},
			want: `sigalg: no classical signature verified: sigalg: unknown algorithm: "rsa"`,
		},
		{
			name: "pq only", signatures: []SignedBy{validPQ},
			want: "sigalg: no classical signature verified",
		},
		{
			name: "invalid classical with valid pq", signatures: []SignedBy{invalidEd, validPQ},
			want: "sigalg: no classical signature verified: sigalg: ed25519 verification failed",
		},
		{
			name: "valid classical with invalid pq", signatures: []SignedBy{validEd, invalidPQ},
			want: "sigalg: PQ signature was asserted but did not verify",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := HybridVerify(message, tt.signatures)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("HybridVerify error = %v, want %q", err, tt.want)
			}
		})
	}
	if err := HybridVerify(message, []SignedBy{validEd}); err != nil {
		t.Fatalf("classical-only error = %v", err)
	}
	if err := HybridVerify(message, []SignedBy{validEd, validPQ}); err != nil {
		t.Fatalf("hybrid error = %v", err)
	}
	if err := HybridVerify(message, []SignedBy{unknown, validEd}); err != nil {
		t.Fatalf("valid classical plus unknown error = %v", err)
	}
}
