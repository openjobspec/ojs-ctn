// Command ojs-ctn is the Conformance Trust Network reference server.
//
// P1 status: in-process JSON-lines ledger + HTTP submission API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openjobspec/ojs-ctn/internal/api"
	"github.com/openjobspec/ojs-ctn/internal/attestlog"
	"github.com/openjobspec/ojs-ctn/internal/metrics"
	"github.com/openjobspec/ojs-ctn/internal/store"
	"github.com/openjobspec/ojs-ctn/internal/witness"
)

const version = "0.1.0-p1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("ojs-ctn", version)
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := fs.String("addr", ":8090", "listen address")
		ledger := fs.String("ledger", "ctn-ledger.jsonl", "path to the JSON-lines ledger file")
		_ = fs.Parse(os.Args[2:])
		if err := serve(*addr, *ledger); err != nil {
			fmt.Fprintln(os.Stderr, "ojs-ctn serve:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ojs-ctn <version|serve [-addr :8090] [-ledger ctn-ledger.jsonl]>")
}

func serve(addr, ledgerPath string) error {
	st, err := store.Open(ledgerPath)
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer st.Close()

	srv := &http.Server{
		Addr: addr,
		Handler: (&api.Server{
			Store:       st,
			Witness:     witness.NewRegistry(witness.Config{}),
			Revocations: attestlog.NewRevocationLog(),
			Metrics:     metrics.NewCounters(),
		}).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "ojs-ctn listening on %s, ledger=%s, entries=%d\n", addr, ledgerPath, st.Count())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-shutdown:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
