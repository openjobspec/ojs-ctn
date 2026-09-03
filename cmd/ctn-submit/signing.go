package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	sigalgpkg "github.com/openjobspec/ojs-ctn/internal/sigalg"
)

func canonicalizeReport(report []byte) ([]byte, error) {
	var probe map[string]any
	if err := json.Unmarshal(report, &probe); err != nil {
		return nil, fmt.Errorf("report is not valid JSON: %w", err)
	}
	canonical, err := json.Marshal(probe)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return canonical, nil
}

func signReport(seed, canonical []byte, algorithm string) (string, error) {
	var signature []byte
	switch algorithm {
	case "ed25519", "":
		privateKey := ed25519.NewKeyFromSeed(seed)
		signature = ed25519.Sign(privateKey, canonical)
	case "ml-dsa-65":
		_, privateKey, err := sigalgpkg.GenerateMLDSA65Key(seed)
		if err != nil {
			return "", fmt.Errorf("keygen: %w", err)
		}
		signature, err = sigalgpkg.SignMLDSA65(privateKey, canonical)
		if err != nil {
			return "", fmt.Errorf("sign: %w", err)
		}
	case "hybrid":
		edPrivateKey := ed25519.NewKeyFromSeed(seed)
		edSignature := ed25519.Sign(edPrivateKey, canonical)
		_, pqPrivateKey, err := sigalgpkg.GenerateMLDSA65Key(seed)
		if err != nil {
			return "", fmt.Errorf("pq keygen: %w", err)
		}
		pqSignature, err := sigalgpkg.SignMLDSA65(pqPrivateKey, canonical)
		if err != nil {
			return "", fmt.Errorf("pq sign: %w", err)
		}
		signature, err = sigalgpkg.EncodeHybridSig(edSignature, pqSignature)
		if err != nil {
			return "", fmt.Errorf("hybrid encode: %w", err)
		}
	default:
		return "", fmt.Errorf("unknown sig-alg %q (use ed25519, ml-dsa-65, or hybrid)", algorithm)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func encodeSubmission(canonical []byte, signature, keyID string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"report":              json.RawMessage(canonical),
		"submitter_signature": signature,
		"submitter_key_id":    keyID,
	})
}
