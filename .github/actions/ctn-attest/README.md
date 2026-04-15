# OJS CTN Attest Action

End-to-end Conformance Trust Network attestation in a single GitHub Action step.

## What it does

1. **Runs the OJS conformance suite** against your backend
2. **Signs the report** with your Ed25519 key
3. **Submits to the CTN log** for public attestation
4. **Posts a summary** to your PR/commit

## Usage

```yaml
- uses: openjobspec/ojs-ctn/.github/actions/ctn-attest@v1
  with:
    server-url: http://localhost:8080
    ctn-endpoint: https://ctn.openjobspec.org
    key-id: did:web:example.com:keys:backend-2026
    seed: ${{ secrets.CTN_SEED }}
    conformance-level: 4
    min-level: 2
    backend-name: ojs-backend-redis
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `server-url` | ✅ | - | Base URL of the OJS backend under test |
| `ctn-endpoint` | ✅ | - | CTN server URL |
| `key-id` | ✅ | - | Submitter key ID |
| `seed` | ✅ | - | Base64-encoded Ed25519 seed (from CI secret) |
| `conformance-level` | ❌ | `4` | Conformance level to test (0–4) |
| `min-level` | ❌ | `0` | Minimum passing level (fails if below) |
| `suites-dir` | ❌ | auto | Path to conformance test suite directory |
| `witnesses` | ❌ | - | Comma-separated witness endpoints |
| `backend-name` | ❌ | - | Human-readable backend name |
| `fail-on-error` | ❌ | `true` | Fail job on submission error |
| `go-version` | ❌ | `1.24` | Go version for building tools |

## Outputs

| Output | Description |
|--------|-------------|
| `entry-id` | CTN entry ID |
| `report-sha256` | SHA-256 of the signed report |
| `conformant-level` | Highest conformance level passed |
| `conformant` | Whether backend is conformant |

## Badge

After attestation, embed a live badge in your README:

```markdown
![OJS Conformance](https://ctn.openjobspec.org/v1/badges/your-backend.svg)
```
