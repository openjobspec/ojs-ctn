package main

import (
	"crypto/ed25519"
	"fmt"
)

type fileReader func(string) ([]byte, error)

func readSeed(path string, readFile fileReader) ([]byte, error) {
	seed, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return seed, nil
}
