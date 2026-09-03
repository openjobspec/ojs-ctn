package main

import (
	"context"
	"io"
	"net/http"
	"os"
)

type witnessEnvironment struct {
	stdout     io.Writer
	readFile   fileReader
	httpClient *http.Client
}

func defaultWitnessEnvironment() witnessEnvironment {
	return witnessEnvironment{
		stdout:     os.Stdout,
		readFile:   os.ReadFile,
		httpClient: http.DefaultClient,
	}
}

func executeWitness(config witnessConfig, environment witnessEnvironment) error {
	if err := config.validate(); err != nil {
		return err
	}
	seed, err := readSeed(config.seedFile, environment.readFile)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()
	client := witnessClient{httpClient: environment.httpClient}
	body, err := client.getEntry(ctx, config.endpoint, config.entryID)
	if err != nil {
		return err
	}
	entry, err := decodeEntry(body)
	if err != nil {
		return err
	}
	canonical, err := canonicalizeReport(entry.Report)
	if err != nil {
		return err
	}
	cosignature, err := encodeCosignature(seed, canonical, config.keyID)
	if err != nil {
		return err
	}
	if config.dryRun {
		writeWitnessOutput(environment.stdout, cosignature)
		return nil
	}
	responseBody, err := client.postCosignature(ctx, config.endpoint, config.entryID, cosignature)
	if err != nil {
		return err
	}
	writeWitnessOutput(environment.stdout, responseBody)
	return nil
}
