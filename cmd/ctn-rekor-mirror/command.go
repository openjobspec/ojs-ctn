package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type runConfig struct {
	ctnEndpoint   string
	rekorEndpoint string
	statePath     string
	interval      time.Duration
	once          bool
	fromSequence  uint64
}

type runEnvironment struct {
	stderr     io.Writer
	httpClient func() *http.Client
	notify     func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)
}

func runCmd(args []string) error {
	config, err := parseRunConfig(args)
	if err != nil {
		return err
	}
	return executeRun(config, runEnvironment{
		stderr:     os.Stderr,
		httpClient: defaultHTTPClient,
		notify:     signal.NotifyContext,
	})
}

func parseRunConfig(args []string) (runConfig, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	ctnEndpoint := fs.String("ctn-endpoint", "", "CTN HTTP base URL (required)")
	rekorEndpoint := fs.String("rekor-endpoint", "", "Rekor base URL (required)")
	statePath := fs.String("state-file", "./ctn-rekor-mirror.state.json", "path to state file")
	interval := fs.Duration("interval", 30*time.Second, "poll interval")
	once := fs.Bool("once", false, "run a single mirror pass and exit")
	fromSequence := fs.Uint64("from", 0, "minimum sequence_number to start mirroring from")
	if err := fs.Parse(args); err != nil {
		return runConfig{}, err
	}
	if *ctnEndpoint == "" || *rekorEndpoint == "" {
		return runConfig{}, errors.New("--ctn-endpoint and --rekor-endpoint are required")
	}
	return runConfig{
		ctnEndpoint:   *ctnEndpoint,
		rekorEndpoint: *rekorEndpoint,
		statePath:     *statePath,
		interval:      *interval,
		once:          *once,
		fromSequence:  *fromSequence,
	}, nil
}

func executeRun(config runConfig, environment runEnvironment) error {
	stateStore := fileStateStore{path: config.statePath}
	state, err := stateStore.Load()
	if err != nil {
		return err
	}
	if state.LastMirroredSeq < config.fromSequence {
		state.LastMirroredSeq = config.fromSequence - 1
	}

	ctn := &httpCTNClient{base: config.ctnEndpoint, http: environment.httpClient()}
	rekor := &httpRekorClient{base: config.rekorEndpoint, http: environment.httpClient()}
	ctx, cancel := environment.notify(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mirror := &Mirror{
		CTN:        ctn,
		Rekor:      rekor,
		State:      state,
		StatePath:  config.statePath,
		stateStore: stateStore,
	}
	if config.once {
		count, err := mirror.Tick(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(environment.stderr, "mirrored %d new entr(y/ies)\n", count)
		return nil
	}
	return runDaemon(ctx, mirror, config.ctnEndpoint, config.interval, environment.stderr)
}
