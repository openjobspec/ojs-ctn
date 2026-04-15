# Changelog

All notable changes to the Conformance Trust Network (CTN) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- P1 append-only ledger with JSON-lines storage
- Ed25519 signing and verification
- CTN server with HTTP API (submissions, entries, log head)
- CLI tools: ctn-submit, ctn-verify, ctn-witness, ctn-audit
- GitHub Actions: ctn-submit, ctn-verify, ctn-attest
- Cosignature witness protocol
- Rekor mirror daemon for transparency log bridging
- P2 registry API with pagination, filtering, and badge generation
- Witness reputation system with diversity enforcement
- ML-DSA-65 (PQC) signature support (placeholder implementation)
- Revocation and attestation decay lifecycle
- Prometheus-style metrics counters
- Comprehensive API documentation and operational runbook

### Security
- Ed25519 + hybrid Ed25519/ML-DSA-65 signature support
- Append-only ledger with SHA-256 integrity
- Cosignature diversity policy enforcement
