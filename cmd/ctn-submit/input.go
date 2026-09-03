package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
)

type fileReader func(string) ([]byte, error)

func readSeed(path string, readFile fileReader) ([]byte, error) {
	seed, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be exactly %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return seed, nil
}

func readReport(path string) ([]byte, error) {
	return readReportFrom(path, os.Stdin, os.ReadFile)
}

func readReportFrom(path string, stdin io.Reader, readFile fileReader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(stdin, 4<<20))
	}
	return readFile(path)
}
