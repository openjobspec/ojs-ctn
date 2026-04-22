package main

import (
	"errors"
	"time"
)

type verifyConfig struct {
	endpoint    string
	entryID     string
	trustFile   string
	timeout     time.Duration
	freshness   time.Duration
	allowAnyKey bool
}

func (c verifyConfig) validate() error {
	if c.endpoint == "" {
		return errors.New("-endpoint required")
	}
	if c.entryID == "" {
		return errors.New("-entry-id required")
	}
	if c.trustFile == "" && !c.allowAnyKey {
		return errors.New("-trust-file required (or pass -allow-any-key for dev)")
	}
	return nil
}
