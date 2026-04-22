package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// State is what we persist between runs.
type State struct {
	LastMirroredSeq uint64            `json:"last_mirrored_sequence"`
	UUIDs           map[string]string `json:"uuids"` // ctn entry_id -> rekor uuid
}

type statePersistence interface {
	Save(State) error
}

type fileStateStore struct {
	path string
}

func (s fileStateStore) Load() (State, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{UUIDs: map[string]string{}}, nil
	}
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}
	if state.UUIDs == nil {
		state.UUIDs = map[string]string{}
	}
	return state, nil
}

func (s fileStateStore) Save(state State) error {
	out, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func loadState(path string) (State, error) {
	return (fileStateStore{path: path}).Load()
}

func saveState(path string, state State) error {
	return (fileStateStore{path: path}).Save(state)
}
