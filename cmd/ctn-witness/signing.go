package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

func encodeCosignature(seed, canonical []byte, keyID string) ([]byte, error) {
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, canonical)
	return json.Marshal(map[string]string{
		"witness_key_id":    keyID,
		"witness_signature": base64.StdEncoding.EncodeToString(signature),
	})
}
