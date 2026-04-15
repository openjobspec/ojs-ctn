// Package crl implements compact certificate-revocation lists used
// by witnesses and verifiers to invalidate compromised log-operator
// or witness signing keys without an online query.
//
// Wire format (network byte order, big-endian):
//
//	u32  version         // currently 1
//	u32  epoch           // monotonic; consumers reject older epochs
//	u32  count           // number of revoked fingerprints
//	[32]byte * count     // SHA-256 fingerprints, sorted ascending
//	[64]byte sig         // Ed25519 signature over all preceding bytes
//
// Sorted fingerprints permit O(log n) membership checks and let
// CRLs be diffed by epoch with a stable byte order.
package crl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const (
	Version    uint32 = 1
	HeaderLen         = 12
	FpLen             = 32
	SigLen            = 64
)

type CRL struct {
	Version uint32
	Epoch   uint32
	Revoked [][32]byte
	Sig     [64]byte
}

func Encode(c *CRL) ([]byte, error) {
	body, err := EncodeUnsigned(c)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+SigLen)
	out = append(out, body...)
	out = append(out, c.Sig[:]...)
	return out, nil
}

// EncodeUnsigned returns the bytes covered by Sig.
func EncodeUnsigned(c *CRL) ([]byte, error) {
	if c.Version != Version {
		return nil, fmt.Errorf("crl: unsupported version %d", c.Version)
	}
	if !sortedAscending(c.Revoked) {
		return nil, errors.New("crl: revoked fingerprints must be sorted ascending")
	}
	out := make([]byte, HeaderLen+len(c.Revoked)*FpLen)
	binary.BigEndian.PutUint32(out[0:4], c.Version)
	binary.BigEndian.PutUint32(out[4:8], c.Epoch)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(c.Revoked)))
	for i, fp := range c.Revoked {
		copy(out[HeaderLen+i*FpLen:], fp[:])
	}
	return out, nil
}

func Decode(buf []byte, issuer ed25519.PublicKey) (*CRL, error) {
	if len(buf) < HeaderLen+SigLen {
		return nil, errors.New("crl: short buffer")
	}
	c := &CRL{
		Version: binary.BigEndian.Uint32(buf[0:4]),
		Epoch:   binary.BigEndian.Uint32(buf[4:8]),
	}
	if c.Version != Version {
		return nil, fmt.Errorf("crl: unsupported version %d", c.Version)
	}
	count := binary.BigEndian.Uint32(buf[8:12])
	want := HeaderLen + int(count)*FpLen + SigLen
	if len(buf) != want {
		return nil, fmt.Errorf("crl: length mismatch: got %d want %d", len(buf), want)
	}
	c.Revoked = make([][32]byte, count)
	for i := uint32(0); i < count; i++ {
		copy(c.Revoked[i][:], buf[HeaderLen+int(i)*FpLen:])
	}
	if !sortedAscending(c.Revoked) {
		return nil, errors.New("crl: revoked list not sorted ascending")
	}
	copy(c.Sig[:], buf[len(buf)-SigLen:])
	body := buf[:len(buf)-SigLen]
	if len(issuer) != ed25519.PublicKeySize {
		return nil, errors.New("crl: bad issuer key size")
	}
	if !ed25519.Verify(issuer, body, c.Sig[:]) {
		return nil, ErrBadSignature
	}
	return c, nil
}

// IsRevoked uses binary search on the sorted Revoked slice.
func (c *CRL) IsRevoked(fp [32]byte) bool {
	i := sort.Search(len(c.Revoked), func(i int) bool {
		return bytes.Compare(c.Revoked[i][:], fp[:]) >= 0
	})
	return i < len(c.Revoked) && c.Revoked[i] == fp
}

var ErrBadSignature = errors.New("crl: signature verification failed")

func sortedAscending(fps [][32]byte) bool {
	for i := 1; i < len(fps); i++ {
		if bytes.Compare(fps[i-1][:], fps[i][:]) >= 0 {
			return false
		}
	}
	return true
}
