package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type fileReader func(string) ([]byte, error)

func loadTrust(path string, allowAnyKey bool) (map[string]ed25519.PublicKey, error) {
	return loadTrustFile(path, allowAnyKey, os.ReadFile)
}

func loadTrustFile(path string, allowAnyKey bool, readFile fileReader) (map[string]ed25519.PublicKey, error) {
	if path == "" && allowAnyKey {
		return map[string]ed25519.PublicKey{}, nil
	}
	raw, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust file: %w", err)
	}
	var encodedKeys map[string]string
	if err := json.Unmarshal(raw, &encodedKeys); err != nil {
		return nil, fmt.Errorf("parse trust file: %w", err)
	}
	trust := make(map[string]ed25519.PublicKey, len(encodedKeys))
	for keyID, encoded := range encodedKeys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey for %q: %w", keyID, err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pubkey for %q is %d bytes, want %d", keyID, len(key), ed25519.PublicKeySize)
		}
		trust[keyID] = ed25519.PublicKey(key)
	}
	if len(trust) == 0 {
		return nil, errors.New("trust file is empty")
	}
	return trust, nil
}
