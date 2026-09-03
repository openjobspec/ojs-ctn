package main

import (
	"encoding/json"
	"fmt"
)

func canonicalizeReport(report json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(report, &value); err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return canonical, nil
}
