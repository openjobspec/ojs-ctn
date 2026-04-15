// Package teequote parses Intel TDX/SGX attestation quote headers.
// We only parse the *header* (the first 48 bytes) — the body and
// signature are produced by the platform DCAP library and verified
// upstream. The header is enough to:
//
//   - reject quotes from a wrong TEE family,
//   - check version compatibility,
//   - extract the QE vendor and user data binding,
//   - quickly fingerprint a quote for caching.
//
// Reference layout (Intel SGX/TDX DCAP Quote v4 / v5):
//
//	off 0 : u16  version            (3 = SGX, 4 = TDX 1.0/1.5, 5 = TDX 1.5+)
//	off 2 : u16  attestation_key_type (2 = ECDSA-P256, 3 = ECDSA-P384)
//	off 4 : u32  tee_type            (0x00000000 = SGX, 0x00000081 = TDX)
//	off 8 : u16  qe_svn
//	off 10: u16  pce_svn
//	off 12: [16]byte qe_vendor_id    (Intel = 939A7233F79C4CA9940A0DB3957F0607)
//	off 28: [20]byte user_data       (caller-bindable arbitrary data)
//	off 48: -- body starts --
package teequote

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const HeaderLen = 48

type TeeType uint32

const (
	TeeSGX TeeType = 0x00000000
	TeeTDX TeeType = 0x00000081
)

type Header struct {
	Version            uint16
	AttestationKeyType uint16
	TeeType            TeeType
	QeSvn              uint16
	PceSvn             uint16
	QeVendorID         [16]byte
	UserData           [20]byte
}

var IntelQeVendor = [16]byte{
	0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9,
	0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
}

func ParseHeader(buf []byte) (*Header, error) {
	if len(buf) < HeaderLen {
		return nil, fmt.Errorf("teequote: short header: %d < %d", len(buf), HeaderLen)
	}
	h := &Header{
		Version:            binary.LittleEndian.Uint16(buf[0:2]),
		AttestationKeyType: binary.LittleEndian.Uint16(buf[2:4]),
		TeeType:            TeeType(binary.LittleEndian.Uint32(buf[4:8])),
		QeSvn:              binary.LittleEndian.Uint16(buf[8:10]),
		PceSvn:             binary.LittleEndian.Uint16(buf[10:12]),
	}
	copy(h.QeVendorID[:], buf[12:28])
	copy(h.UserData[:], buf[28:48])
	return h, nil
}

// Validate enforces the bare-minimum invariants. Use this as a fast
// triage before calling the heavy DCAP signature verification.
func (h *Header) Validate() error {
	if h == nil {
		return errors.New("teequote: nil header")
	}
	switch h.Version {
	case 3, 4, 5:
	default:
		return fmt.Errorf("teequote: unsupported quote version %d", h.Version)
	}
	switch h.AttestationKeyType {
	case 2, 3:
	default:
		return fmt.Errorf("teequote: unsupported attestation key type %d", h.AttestationKeyType)
	}
	switch h.TeeType {
	case TeeSGX, TeeTDX:
	default:
		return fmt.Errorf("teequote: unknown TEE type 0x%08x", uint32(h.TeeType))
	}
	if h.Version >= 4 && h.TeeType != TeeTDX {
		return fmt.Errorf("teequote: version %d requires TDX type", h.Version)
	}
	if h.Version == 3 && h.TeeType != TeeSGX {
		return fmt.Errorf("teequote: version 3 requires SGX type")
	}
	return nil
}

// IsIntelQe reports whether the quote was produced by an Intel
// quoting enclave. Off-vendor quotes are accepted by the parser but
// callers usually want to gate on this.
func (h *Header) IsIntelQe() bool {
	return bytes.Equal(h.QeVendorID[:], IntelQeVendor[:])
}

// Encode is the inverse of ParseHeader, useful for tests and for
// constructing fixtures.
func Encode(h *Header) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	out := make([]byte, HeaderLen)
	binary.LittleEndian.PutUint16(out[0:2], h.Version)
	binary.LittleEndian.PutUint16(out[2:4], h.AttestationKeyType)
	binary.LittleEndian.PutUint32(out[4:8], uint32(h.TeeType))
	binary.LittleEndian.PutUint16(out[8:10], h.QeSvn)
	binary.LittleEndian.PutUint16(out[10:12], h.PceSvn)
	copy(out[12:28], h.QeVendorID[:])
	copy(out[28:48], h.UserData[:])
	return out, nil
}
