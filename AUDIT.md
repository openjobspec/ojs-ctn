## 1. Final summary

- All repository-local findings `CTN-001` through `CTN-010` are implemented.
- Every high-risk seam received characterization coverage before production changes. The guardrail freezes JSONL bytes and hashes, HTTP routes/status/bodies/limits, canonical bytes and signatures, CLI stdout/stderr/exit codes, mirror state bytes/replacement, registry errors, and freshness thresholds.
- Exported APIs and types, dependencies, HTTP surface, ledger wire format, canonicalization, signatures, and CLI flags remain unchanged.
- The pre-existing `ctn-audit` split was preserved. No files were staged or committed, and the safety stash was not modified.

## 2. Final dispositions and evidence

| ID | disposition | implementation evidence | behavior guardrail |
|---|---|---|---|
| CTN-001 | Complete | `cmd/ctn-audit/{main,client,analysis,verification,output}.go` | `cmd/ctn-audit/main_test.go` text-output characterization |
| CTN-002 | Complete | `internal/store/{store,persistence,index,registry}.go` | `store_characterization_test.go`: exact entry/cosign JSONL bytes, head hash, replay tolerance/replacement, defensive copies, flush/sync rollback, retry sequence, close/rollback errors |
| CTN-003 | Complete | `internal/api/{routes,response,ledger_handler,entry_handler,cosign_handler,lifecycle_handler}.go`; exported `Server` retained | `server_characterization_test.go`: all registered route prefixes, exact representative bodies/status/content types, 4 MiB and 64 KiB boundaries |
| CTN-004 | Complete | `cmd/ctn-submit/{config,input,signing,client,output,command}.go` | `cmd/ctn-submit/main_test.go`: validation order, stdin limit, all algorithm branches, exact canonical signatures/request JSON/headers/output/exits |
| CTN-005 | Complete | `cmd/ctn-verify/{config,trust,canonical,client,verification,output,command}.go` | `cmd/ctn-verify/main_test.go`: trust errors, canonical bytes, request shape, integrity/signature failure order, warning, HTTP errors, process output/exits |
| CTN-006 | Complete | `cmd/ctn-witness/{config,input,entry,canonical,signing,client,output,command}.go` | `cmd/ctn-witness/main_test.go`: validation order, GET/POST ordering and headers, signature/request bytes, dry-run/server output, errors/exits |
| CTN-007 | Complete | `cmd/ctn-rekor-mirror/{command,daemon,ctn_client,rekor_client,state,mirror,http}.go` | `mirror_characterization_test.go`: state bytes/mode, atomic replacement failure, client wire shapes/errors, idempotency, save-failure semantics, one-shot output |
| CTN-008 | Complete | `internal/store/report_projection.go`; registry queries decode through one schema owner | `report_projection_characterization_test.go`: precedence, missing/invalid/wrong-type fallbacks, malformed-report grouping, newest-first and alphabetical ordering |
| CTN-009 | Complete | `internal/sigalg/{registry,verify,acceptance}.go`; hybrid encoding remains separate | `policy_characterization_test.go`: exact metadata/order, size errors, dispatch behavior, aggregate hybrid acceptance and error ordering |
| CTN-010 | Complete | `internal/attestlog/{decay,freshness,revocation}.go` | `decay_characterization_test.go`: exact threshold/default/negative/future behavior, revocation precedence, error strings, defensive snapshots |

## 3. Preserved contracts

1. Ledger entry and cosignature JSONL field order, bytes, newline placement, hashes, IDs, sequence/head behavior, replay orphan tolerance, and cosignature replacement are unchanged on successful writes.
2. Store write failures now roll back durable bytes before index mutation; rollback and close failures retain their underlying errors.
3. `Server`, every route, response status/body/content type, request limit, and `logging(mux)` middleware position are unchanged.
4. Submit, verify, witness, and audit command names, flags/defaults, validation order, canonicalization, signatures, request headers/bodies, warnings, stdout/stderr, and exit codes are unchanged.
5. Mirror polling remains ticker-driven with one head entry per tick; state JSON indentation/key order/no-trailing-newline, `0600` temporary-file mode, rename replacement, idempotency, and in-memory save-failure semantics are unchanged.
6. `CTNClient.HeadIDs` was not removed: it has zero callers but is exported, and removal would violate the frozen API requirement.
7. `sigalg.All()` ordering/membership, hybrid metadata lookup, all public functions/types, and existing error text/order are unchanged.
8. Freshness remains `Outdated` only when `age > MaxAge`; zero still selects 90 days and revocation still takes precedence.

## 4. Assumptions and exclusions

- “Remove reserved zero-caller private surface only if unexported” was applied literally; exported `HeadIDs` remains.
- Repeated canonicalization in independently shipped CLI binaries remains intentional boundary duplication.
- Product changes, documentation/API mismatches, protocol expansion, and replacement of placeholder ML-DSA cryptography remain out of scope.
- No dependencies were added and no exported contract was intentionally changed.

## 5. Verification

Final result: **PASS** on 2026-08-03.

```text
PASS  GOWORK=off GOFLAGS=-mod=readonly go test ./... -race
PASS  GOWORK=off GOFLAGS=-mod=readonly go vet ./...
PASS  git diff --check
```
