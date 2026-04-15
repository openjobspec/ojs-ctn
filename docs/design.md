# CTN Design (P0)

## Problem

Conformance reports today are PDFs. There is no machine-comparable view of
"which backends pass which OJS levels." Vendor self-attestation is unverifiable.

## Goal

Build a **public, append-only, witness-cosigned ledger** of `SuiteReport`
documents (schema v1.1 — see `ojs-conformance/lib/schema.go::SuiteReport`).

## Trust Model

1. **Submitter signs** the canonical-JSON SHA-256 of the report with an
   ed25519 (P0/P1) or ML-DSA-65 (P3+) key.
2. **CTN log appends** a transparency-log entry (Merkle inclusion proof).
3. **Witnesses** (independent third parties: CNCF TAG-Security members,
   academics, peer maintainers) co-sign the log head periodically.
4. **Verifier** (any client) can replay the inclusion proof and check
   submitter + witness signatures offline.

## Data Model

### Submission

```json
{
  "report": { ... },          // SuiteReport v1.1, exactly as emitted
  "submitter_signature": "...",
  "submitter_key_id": "did:web:openjobspec.org:keys:redis-backend-2026"
}
```

### Log entry

```json
{
  "entry_id": "uuidv7",
  "logged_at": "rfc3339",
  "report_sha256": "hex",
  "report": { ... },
  "submitter_signature": "...",
  "submitter_key_id": "...",
  "merkle_proof": { "root": "...", "path": [...] },
  "witness_cosignatures": [
    { "key_id": "...", "signature": "...", "signed_at": "rfc3339" }
  ]
}
```

## API surface (P1 target)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/submissions` | Append a new submission |
| GET | `/v1/entries/:id` | Retrieve a logged entry with proof |
| GET | `/v1/log/head` | Current Merkle root + witness cosignatures |
| GET | `/v1/log/proof?from=...&to=...` | Consistency proof between two heads |
| GET | `/v1/registry?backend=...&level=4` | Convenience query (built on top of entries) |

## Storage

- **P0 / P1:** SQLite + filesystem blob store; sufficient for design partners.
- **P2+:** Postgres + S3; multi-region read replicas; IPFS mirror.

## Open questions

- Which Merkle log implementation? Considering `transparency-dev/trillian`
  vs. building a simpler purpose-built log. **Decision exits P0.**
- Witness onboarding model — invite-only (P2) → standards-body governed (P4).
- Revocation: do we ever remove an entry? **Default: no, never** — append-only.
  Compromised submitter keys are handled by publishing a revocation marker
  entry, not deletion.

## Dependencies on other moonshots

- **W0 F2:** `SuiteReport` v1.1 — done.
- **W0 F3:** codec-server `Signer` plugin — done.
- **M1 (Verifiable Compute):** future integration; signed compute proofs
  could be submitted to CTN as a separate stream.

## References

- Certificate Transparency RFC 6962 — <https://datatracker.ietf.org/doc/html/rfc6962>
- Sigstore Rekor — <https://github.com/sigstore/rekor>
- Trillian — <https://github.com/transparency-dev/trillian>
- in-toto attestation — <https://github.com/in-toto/attestation>
