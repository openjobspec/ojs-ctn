package main

import (
	"io"
	"net/http"
	"os"
)

type verifyEnvironment struct {
	stderr     io.Writer
	readFile   fileReader
	httpClient *http.Client
}

func defaultVerifyEnvironment() verifyEnvironment {
	return verifyEnvironment{
		stderr:     os.Stderr,
		readFile:   os.ReadFile,
		httpClient: http.DefaultClient,
	}
}

func executeVerify(config verifyConfig, environment verifyEnvironment) error {
	if err := config.validate(); err != nil {
		return err
	}
	trust, err := loadTrustFile(config.trustFile, config.allowAnyKey, environment.readFile)
	if err != nil {
		return err
	}
	body, err := (entryClient{httpClient: environment.httpClient}).get(config.endpoint, config.entryID, config.timeout)
	if err != nil {
		return err
	}
	entry, err := decodeEntry(body, config.entryID)
	if err != nil {
		return err
	}
	if err := verifyReportDigest(entry); err != nil {
		return err
	}
	if err := verifyFreshness(entry, config.freshness); err != nil {
		return err
	}
	if config.allowAnyKey {
		writeAllowAnyKeyWarning(environment.stderr)
		return nil
	}
	return verifySignature(entry, trust)
}
