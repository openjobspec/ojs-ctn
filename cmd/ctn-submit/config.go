package main

import (
	"errors"
	"time"
)

type submitConfig struct {
	endpoint   string
	keyID      string
	seedFile   string
	reportPath string
	sigAlg     string
	timeout    time.Duration
	dryRun     bool
}

func (c submitConfig) validate() error {
	if c.keyID == "" {
		return errors.New("-key-id required")
	}
	if c.seedFile == "" {
		return errors.New("-seed-file required")
	}
	if c.reportPath == "" {
		return errors.New("-report required (use - for stdin)")
	}
	if !c.dryRun && c.endpoint == "" {
		return errors.New("-endpoint required (or use -dry-run)")
	}
	return nil
}
