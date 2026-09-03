package main

import (
	"encoding/json"
)

// canonicalize matches ctn-submit's P1 strategy: json.Unmarshal into a
// generic value, then re-Marshal. Go's encoding/json sorts map keys
// alphabetically, which is enough determinism for P1. P2 will switch
// the whole pipeline to RFC 8785 JCS.
func canonicalize(raw json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
