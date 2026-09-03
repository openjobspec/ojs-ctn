package main

import (
	"io"
	"net/http"
	"os"
)

type submitEnvironment struct {
	stdin      io.Reader
	stdout     io.Writer
	readFile   fileReader
	httpClient *http.Client
}

func defaultSubmitEnvironment() submitEnvironment {
	return submitEnvironment{
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		readFile:   os.ReadFile,
		httpClient: http.DefaultClient,
	}
}

func executeSubmit(config submitConfig, environment submitEnvironment) error {
	if err := config.validate(); err != nil {
		return err
	}
	seed, err := readSeed(config.seedFile, environment.readFile)
	if err != nil {
		return err
	}
	report, err := readReportFrom(config.reportPath, environment.stdin, environment.readFile)
	if err != nil {
		return err
	}
	canonical, err := canonicalizeReport(report)
	if err != nil {
		return err
	}
	signature, err := signReport(seed, canonical, config.sigAlg)
	if err != nil {
		return err
	}
	body, err := encodeSubmission(canonical, signature, config.keyID)
	if err != nil {
		return err
	}
	if config.dryRun {
		return writeSubmissionOutput(environment.stdout, body)
	}
	responseBody, err := (submissionClient{httpClient: environment.httpClient}).post(config.endpoint, body, config.timeout)
	if err != nil {
		return err
	}
	return writeSubmissionOutput(environment.stdout, responseBody)
}
