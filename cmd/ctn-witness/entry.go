package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

func decodeEntry(body []byte) (Entry, error) {
	var entry Entry
	if err := json.Unmarshal(body, &entry); err != nil {
		return Entry{}, fmt.Errorf("decode entry: %w", err)
	}
	if len(entry.Report) == 0 {
		return Entry{}, errors.New("entry has empty report")
	}
	return entry, nil
}
