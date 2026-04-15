# ojs-ctn — Conformance Trust Network

![labs](https://img.shields.io/badge/OJS-Labs-blueviolet)

> **Part of [OJS Labs](../STABILITY.md#ojs-labs)** — forward-looking R&D, not part of the core release train.

The CTN is a public, signed, append-only ledger of conformance test results.
Backends submit signed `SuiteReport` v1.1 documents; the registry hosts
witnessed entries, exposes a queryable API, and powers `openjobspec.org/registry`.

## Why this exists

OJS conformance results today live as opaque PDFs. CTN turns them into a
**verifiable, comparable, machine-readable trust artifact** — the equivalent
of the CA/Browser Forum's CT log for spec compliance.

## Quick start (P0)

```bash
go run ./cmd/ojs-ctn version
```

## Architecture (target P1)

```
        +-------------+        +----------------+
SDK --> |  CTN API    | -----> |  Append-only   | ---> Public Mirror
(POST   | (HTTP+JSON) |        |  Ledger Store  |       (S3 + IPFS)
 v1.1   +------+------+        +--------+-------+
report)        |                        |
               v                        v
        +-------------+         +----------------+
        |  Witness    |         |  Query API     | ---> openjobspec.org
        |  Co-signers |         |  (HTTP+GraphQL)|       /registry
        +-------------+         +----------------+
```

## Roadmap

| Phase | Deliverable |
|---|---|
| P0 (this) | Skeleton, design.md, conformance v1.1 schema dependency wired |
| P1 | Append-only store + HTTP submission API + ed25519 verification |
| P2 | Witness co-signing + Sigstore Rekor mirror + public web UI |
| P3 | GraphQL query API + ML-DSA PQC signatures + 3 design-partner backends submitting weekly |
| P4 | Public GA + CNCF-hosted instance |

## License

Apache-2.0
