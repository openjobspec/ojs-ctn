# ojs-ctn — Conformance Trust Network

![labs](https://img.shields.io/badge/OJS-Labs-blueviolet)

> **Part of [OJS Labs](https://github.com/openjobspec/openjobspec/blob/main/STABILITY.md#ojs-labs)** — forward-looking R&D, not part of the core release train.
>
> **Experimental support boundary:** this repository has no production-readiness,
> compatibility, hosted-service, or release-support commitment. Ledger and API
> formats may change without notice. Maintenance is best-effort; report
> vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

CTN explores a signed, append-only ledger of conformance test results.
Backends can submit signed `SuiteReport` v1.1 documents to an experimental
registry implementation that stores witnessed entries and exposes a queryable
API. A future deployment could power a public registry; none is supported here.

## Why this exists

OJS conformance results today live as opaque PDFs. CTN turns them into a
**verifiable, comparable, machine-readable trust artifact** — the equivalent
of the CA/Browser Forum's CT log for spec compliance.

## Development check

```bash
go run ./cmd/ojs-ctn version
```

## Experimental architecture

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

## Current status

The repository contains an experimental local append-only ledger, HTTP API,
Ed25519 signing and verification paths, witness tooling, registry projections,
and a Rekor mirror prototype. It does not provide a supported hosted registry,
an availability commitment, or a stable wire/API contract.

The ML-DSA path is explicitly a placeholder implementation. It must not be
treated as production post-quantum cryptography or as a security control.

## License

[Apache-2.0](LICENSE)
