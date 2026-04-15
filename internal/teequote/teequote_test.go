package teequote

import (
	"bytes"
	"testing"
)

func validTDXHeader() *Header {
	h := &Header{
		Version:            4,
		AttestationKeyType: 2,
		TeeType:            TeeTDX,
		QeSvn:              7,
		PceSvn:             11,
		QeVendorID:         IntelQeVendor,
	}
	copy(h.UserData[:], []byte("attest-binding-12345"))
	return h
}

func TestEncodeParse_RoundTrip(t *testing.T) {
	in := validTDXHeader()
	buf, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != HeaderLen {
		t.Fatalf("len=%d", len(buf))
	}
	out, err := ParseHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != 4 || out.TeeType != TeeTDX || out.QeSvn != 7 || out.PceSvn != 11 {
		t.Errorf("decoded=%+v", out)
	}
	if !bytes.Equal(out.UserData[:], in.UserData[:]) {
		t.Error("user_data corrupted")
	}
	if !out.IsIntelQe() {
		t.Error("expected Intel QE")
	}
}

func TestParseHeader_Short(t *testing.T) {
	if _, err := ParseHeader(make([]byte, 10)); err == nil {
		t.Error("expected short-header error")
	}
}

func TestValidate_BadVersion(t *testing.T) {
	h := validTDXHeader()
	h.Version = 99
	if err := h.Validate(); err == nil {
		t.Error("expected version error")
	}
}

func TestValidate_BadKeyType(t *testing.T) {
	h := validTDXHeader()
	h.AttestationKeyType = 99
	if err := h.Validate(); err == nil {
		t.Error("expected key-type error")
	}
}

func TestValidate_UnknownTEE(t *testing.T) {
	h := validTDXHeader()
	h.TeeType = 0xDEADBEEF
	if err := h.Validate(); err == nil {
		t.Error("expected TEE-type error")
	}
}

func TestValidate_VersionTeeMismatchTDX(t *testing.T) {
	h := validTDXHeader()
	h.Version = 4
	h.TeeType = TeeSGX
	if err := h.Validate(); err == nil {
		t.Error("v4+TeeSGX should be rejected")
	}
}

func TestValidate_VersionTeeMismatchSGX(t *testing.T) {
	h := validTDXHeader()
	h.Version = 3
	h.TeeType = TeeTDX
	if err := h.Validate(); err == nil {
		t.Error("v3+TeeTDX should be rejected")
	}
}

func TestIsIntelQe_FalseForOtherVendor(t *testing.T) {
	h := validTDXHeader()
	for i := range h.QeVendorID {
		h.QeVendorID[i] = 0xff
	}
	if h.IsIntelQe() {
		t.Error("non-Intel vendor incorrectly identified")
	}
}

func TestEncode_RejectsInvalid(t *testing.T) {
	h := validTDXHeader()
	h.Version = 0
	if _, err := Encode(h); err == nil {
		t.Error("expected encode-rejects-invalid")
	}
}

func TestParseHeader_AcceptsSGXv3(t *testing.T) {
	h := &Header{
		Version: 3, AttestationKeyType: 2, TeeType: TeeSGX,
		QeVendorID: IntelQeVendor,
	}
	buf, err := Encode(h)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Validate(); err != nil {
		t.Errorf("SGX v3 should be valid: %v", err)
	}
}
