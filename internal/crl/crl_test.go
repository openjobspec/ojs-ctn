package crl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"sort"
	"testing"
)

func mkCRL(t *testing.T, count int) (*CRL, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fps := make([][32]byte, count)
	for i := range fps {
		fps[i] = sha256.Sum256([]byte{byte(i), byte(i >> 8)})
	}
	sort.Slice(fps, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if fps[i][k] != fps[j][k] {
				return fps[i][k] < fps[j][k]
			}
		}
		return false
	})
	c := &CRL{Version: Version, Epoch: 7, Revoked: fps}
	body, err := EncodeUnsigned(c)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.Sig[:], ed25519.Sign(priv, body))
	return c, pub, priv
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	c, pub, _ := mkCRL(t, 8)
	buf, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(buf, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 7 || len(got.Revoked) != 8 {
		t.Errorf("decoded=%+v", got)
	}
	for i := range c.Revoked {
		if c.Revoked[i] != got.Revoked[i] {
			t.Errorf("fp[%d] mismatch", i)
		}
	}
}

func TestDecode_RejectsBadSignature(t *testing.T) {
	c, pub, _ := mkCRL(t, 4)
	buf, _ := Encode(c)
	buf[len(buf)-1] ^= 0xff
	if _, err := Decode(buf, pub); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

func TestDecode_RejectsTamperedBody(t *testing.T) {
	c, pub, _ := mkCRL(t, 4)
	buf, _ := Encode(c)
	buf[5] ^= 0xff // perturb epoch
	if _, err := Decode(buf, pub); err != ErrBadSignature {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

func TestDecode_RejectsLengthMismatch(t *testing.T) {
	c, pub, _ := mkCRL(t, 4)
	buf, _ := Encode(c)
	if _, err := Decode(buf[:len(buf)-1], pub); err == nil {
		t.Error("expected length-mismatch error")
	}
}

func TestDecode_RejectsBadVersion(t *testing.T) {
	c, pub, _ := mkCRL(t, 2)
	buf, _ := Encode(c)
	buf[3] = 99
	if _, err := Decode(buf, pub); err == nil {
		t.Error("expected version error")
	}
}

func TestEncode_RejectsUnsorted(t *testing.T) {
	a := sha256.Sum256([]byte("a"))
	b := sha256.Sum256([]byte("b"))
	hi, lo := a, b
	if string(a[:]) < string(b[:]) {
		hi, lo = b, a
	}
	c := &CRL{Version: Version, Revoked: [][32]byte{hi, lo}}
	if _, err := EncodeUnsigned(c); err == nil {
		t.Error("expected sort-order error")
	}
}

func TestIsRevoked(t *testing.T) {
	c, _, _ := mkCRL(t, 16)
	for _, fp := range c.Revoked {
		if !c.IsRevoked(fp) {
			t.Errorf("expected fp %x revoked", fp)
		}
	}
	var miss [32]byte
	miss[0] = 0xff
	miss[31] = 0xff
	if c.IsRevoked(miss) {
		t.Error("non-revoked fp reported as revoked")
	}
}

func TestEmptyCRL(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := &CRL{Version: Version, Epoch: 1}
	body, _ := EncodeUnsigned(c)
	copy(c.Sig[:], ed25519.Sign(priv, body))
	buf, _ := Encode(c)
	got, err := Decode(buf, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Revoked) != 0 {
		t.Error("expected empty revoked list")
	}
	var any [32]byte
	if got.IsRevoked(any) {
		t.Error("empty CRL must not revoke anything")
	}
}
