package main

import (
	"errors"
	"time"
)

type witnessConfig struct {
	endpoint string
	entryID  string
	keyID    string
	seedFile string
	timeout  time.Duration
	dryRun   bool
}

func (c witnessConfig) validate() error {
	if c.endpoint == "" {
		return errors.New("-endpoint required")
	}
	if c.entryID == "" {
		return errors.New("-entry-id required")
	}
	if c.keyID == "" {
		return errors.New("-witness-key-id required")
	}
	if c.seedFile == "" {
		return errors.New("-seed-file required")
	}
	return nil
}
