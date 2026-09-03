# Contributing to ojs-ctn

`ojs-ctn` is an OJS Labs experiment, not a stable trust service. Do not assume
API, ledger, signature-policy, or operational compatibility. Proposals may be
redesigned as the research direction changes.

Use Go 1.24 or newer. Preserve characterized ledger bytes, signatures, and HTTP
contracts unless a change explicitly updates the experimental contract. Run:

```bash
GOWORK=off GOFLAGS=-mod=readonly go test ./... -race
GOWORK=off GOFLAGS=-mod=readonly go vet ./...
```

Never describe the placeholder ML-DSA path as production cryptography. Use the
private process in [SECURITY.md](SECURITY.md) for vulnerabilities.
Contributions are licensed under Apache-2.0.
