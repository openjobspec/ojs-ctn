package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

type verifyOutcome int

const (
	verifyOK verifyOutcome = iota
	verifyUnknown
	verifyBad
	verifySkip
)

func verifyEntry(e entry, trust map[string]ed25519.PublicKey) verifyOutcome {
	if trust == nil {
		return verifySkip
	}
	pk, ok := trust[e.SubmitterKeyID]
	if !ok {
		return verifyUnknown
	}
	sig, err := base64.StdEncoding.DecodeString(e.SubmitterSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return verifyBad
	}
	canonical, err := canonicalize(e.Report)
	if err != nil {
		return verifyBad
	}
	if !ed25519.Verify(pk, canonical, sig) {
		return verifyBad
	}
	// Sanity: ReportSHA256 should match canonicalised bytes.
	sum := sha256.Sum256(canonical)
	if e.ReportSHA256 != "" && e.ReportSHA256 != hexEncode(sum[:]) {
		return verifyBad
	}
	return verifyOK
}

func canonicalize(raw json.RawMessage) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

func loadTrust(path string) (map[string]ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string]ed25519.PublicKey, len(m))
	for k, v := range m {
		pk, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("decode key %s: %w", k, err)
		}
		if len(pk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %s: bad size %d", k, len(pk))
		}
		out[k] = ed25519.PublicKey(pk)
	}
	return out, nil
}
