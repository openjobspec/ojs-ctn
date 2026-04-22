// Package api exposes the CTN HTTP surface defined in
// ojs-ctn/docs/design.md (P1 subset + P2 registry).
//
//	POST /v1/submissions   - append a new entry
//	GET  /v1/entries/:id   - retrieve a logged entry
//	GET  /v1/log/head      - current ledger head
//	GET  /v1/registry      - list all attestations (paginated)
//	GET  /v1/registry/backends        - list backend summaries
//	GET  /v1/registry/backends/:name  - entries for a backend
//	GET  /v1/badges/:backend.svg      - SVG badge for a backend
//	GET  /healthz          - liveness probe
package api

import (
	"github.com/openjobspec/ojs-ctn/internal/attestlog"
	"github.com/openjobspec/ojs-ctn/internal/metrics"
	"github.com/openjobspec/ojs-ctn/internal/store"
	"github.com/openjobspec/ojs-ctn/internal/witness"
)

// Server is the HTTP handler bundle.
type Server struct {
	Store       *store.Store
	Witness     *witness.Registry
	Revocations *attestlog.RevocationLog
	Metrics     *metrics.Counters
}
