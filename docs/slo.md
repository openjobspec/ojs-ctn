# SLO Definitions

This document defines the Service Level Objectives (SLOs) for the Conformance
Transparency Network (CTN). These targets apply to the production deployment of
the CTN log server.

## SLO Summary

| SLO | Target | Measurement Method |
|-----|--------|--------------------|
| Submission latency (p95) | ≤ 2 s | Prometheus histogram `ctn_submission_duration_seconds` (0.95 quantile) |
| Verification latency (p95) | ≤ 200 ms | Prometheus histogram `ctn_verification_duration_seconds` (0.95 quantile) |
| Read availability | 99.99 % | Uptime ratio of GET endpoints over a 30-day rolling window |
| Submit availability | 99.9 % | Uptime ratio of POST `/v1/submissions` over a 30-day rolling window |

## Definitions

### Submission Latency

Time measured from the moment the CTN server receives a `POST /v1/submissions`
request to the moment the response (including the signed inclusion proof) is
returned to the caller. The 95th-percentile of this duration MUST remain at or
below **2 seconds**.

This covers:
1. Signature verification of the submitter's ed25519 signature.
2. SuiteReport validation.
3. Appending the entry to the append-only log.
4. Computing the new Merkle tree root and inclusion proof.
5. Returning the signed response.

### Verification Latency

Time measured from receipt of a `GET /v1/entries/{id}` request to the delivery
of the response containing the entry and its Merkle inclusion proof. The
95th-percentile MUST remain at or below **200 milliseconds**.

### Read Availability

The fraction of successful (non-5xx) responses for all read-only endpoints
(`GET /v1/entries/*`, `GET /v1/log/head`, `GET /v1/registry/*`,
`GET /v1/badges/*`, `GET /v1/witnesses/*`) measured over a 30-day rolling
window. Target: **99.99 %** (≤ 4.3 minutes of downtime per 30 days).

### Submit Availability

The fraction of successful (non-5xx) responses for `POST /v1/submissions`
measured over a 30-day rolling window. Target: **99.9 %** (≤ 43.2 minutes of
downtime per 30 days). The submit path has a lower target because it involves
write operations and Merkle tree updates.

## Measurement Infrastructure

### Prometheus Metrics

The CTN server exposes a `/v1/metrics` endpoint in Prometheus exposition format.
Key metrics used for SLO tracking:

| Metric | Type | Description |
|--------|------|-------------|
| `ctn_submission_duration_seconds` | Histogram | End-to-end submission handling time |
| `ctn_verification_duration_seconds` | Histogram | Entry retrieval and proof generation time |
| `ctn_http_requests_total` | Counter | Total requests by method, path, and status code |
| `ctn_http_request_duration_seconds` | Histogram | General request duration by endpoint |
| `ctn_log_entries_total` | Counter | Total entries appended to the log |
| `ctn_merkle_tree_size` | Gauge | Current number of leaves in the Merkle tree |
| `ctn_witness_cosignatures_total` | Counter | Witness cosignatures received |

### Health Checks

The `/healthz` endpoint returns `200 OK` when the server is healthy and ready
to serve traffic. A health check failure means:
- The append-only log file is not writable, **or**
- The in-memory Merkle tree is inconsistent with the persisted log, **or**
- The ed25519 signing key is unavailable.

External uptime monitors (e.g., Prometheus blackbox exporter) should probe
`/healthz` every 15 seconds.

## Breach Response

When an SLO is breached or at risk of breaching:

### Latency SLO Breach

1. **Alert fires** — Prometheus alerting rule triggers when the p95 exceeds the
   target for more than 5 minutes.
2. **Triage** — On-call investigates whether the cause is load-related,
   storage I/O, or Merkle tree recomputation overhead.
3. **Mitigate** — Scale horizontally (read replicas for GET endpoints) or
   vertically (faster storage). Submission latency may require optimizing the
   Merkle append path.
4. **Post-incident** — Document root cause; adjust capacity planning.

### Availability SLO Breach

1. **Alert fires** — Error budget consumption rate exceeds the burn-rate
   threshold (e.g., 14.4× for a 1-hour window or 6× for a 6-hour window).
2. **Page on-call** — Availability breaches are always paging severity.
3. **Mitigate** — Restore service; if the log file is corrupted, follow the
   incident response procedure in `runbook.md`.
4. **Post-incident** — Publish a post-mortem; review whether the SLO target is
   still appropriate.

### Error Budget Policy

Each SLO has a 30-day rolling error budget. When more than **50 %** of the
budget is consumed, new feature deployments are frozen and engineering effort is
redirected to reliability improvements until the budget recovers.
