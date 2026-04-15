# `ctn-submit` GitHub Action

Sign and append your Conformance Transparency Network report from CI in one step.

```yaml
- name: Submit conformance report to CTN
  uses: openjobspec/ojs-ctn/.github/actions/ctn-submit@main
  with:
    endpoint: https://staging.ctn.openjobspec.org
    key-id:   did:web:example.com:keys:backend-2026
    seed:     ${{ secrets.CTN_SEED_B64 }}
    report:   ./conformance-report.json
```

## Inputs

| Name | Required | Description |
|------|----------|-------------|
| `endpoint` | yes | CTN base URL. |
| `key-id` | yes | Submitter key ID; must already be in the CTN allowlist. |
| `seed` | yes | Base64-encoded 32-byte ed25519 seed. **Source from a GitHub secret only.** |
| `report` | yes | Path to the SuiteReport JSON to sign. |
| `ctn-submit-version` | no | Git ref to build `ctn-submit` from. Defaults to the action ref. |
| `fail-on-error` | no | `false` downgrades submission failures to a warning. Default `true`. |
| `go-version` | no | Go toolchain to install. Default `1.24`. |

## Outputs

| Name | Description |
|------|-------------|
| `entry-id` | The CTN entry ID returned by the server. |
| `report-sha256` | SHA-256 of the canonical bytes that were signed. |

## Generating a key for CI

```bash
dd if=/dev/urandom of=seed.bin bs=32 count=1
base64 -i seed.bin                 # paste into GitHub Secret CTN_SEED_B64
ojs-attest keygen -seed seed.bin -pub pub.bin
base64 -i pub.bin                  # send to OJS to allowlist your key-id
```

Rotate keys quarterly; CTN entries remain verifiable as long as the historical
public key stays in the trust file used by `ctn-verify`.

## What this action does, end to end

1. Installs Go and builds `ctn-submit` from the requested ref.
2. Decodes your secret seed into a 32-byte file (chmod 600, never logged).
3. Runs `ctn-submit -endpoint ... -key-id ... -seed-file ... -report ...`
4. Parses the response JSON and exposes `entry_id` + `report_sha256` as outputs
   so downstream steps can attach them to a release, comment them on a PR, etc.

## Verifying from the same workflow

```yaml
- name: Verify CTN entry was logged
  uses: openjobspec/ojs-ctn/.github/actions/ctn-verify@main  # forthcoming
  with:
    endpoint:   https://staging.ctn.openjobspec.org
    entry-id:   ${{ steps.ctn.outputs.entry-id }}
    trust-file: ./.ctn/trust.json
```
