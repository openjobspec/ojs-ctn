# CTN API Reference

The Conformance Transparency Network (CTN) is a public, append-only,
witness-cosigned ledger of OJS conformance `SuiteReport` documents. All entries
are signed with ed25519, organized in a Merkle tree for tamper-evident
verification, and cosigned by independent witnesses.

**Base URL:** `https://ctn.openjobspec.org` (production)

## Authentication

Submission and witness endpoints require an ed25519 signature in the request
body. Read endpoints are public and require no authentication.

## Content Type

All request and response bodies use `application/json` unless otherwise noted.

---

## Endpoints

### 1. POST /v1/submissions

Submit a new conformance report to the transparency log.

**Description:** Accepts a `SuiteReport` document signed by the submitter's
ed25519 private key. The server validates the signature, appends the entry to
the append-only log, computes a Merkle inclusion proof, and returns the entry
with its log position.

**Request Body:**

```json
{
  "suite_report": {
    "backend": "ojs-backend-redis",
    "version": "0.3.0",
    "conformance_level": 4,
    "total_tests": 256,
    "passed": 256,
    "failed": 0,
    "skipped": 0,
    "timestamp": "2025-01-15T10:30:00Z",
    "runner_version": "1.2.0",
    "metadata": {
      "go_version": "1.24.0",
      "redis_version": "7.2.4"
    }
  },
  "submitter_public_key": "MCowBQYDK2VwAyEA2b5y...",
  "submitter_signature": "dGhpcyBpcyBhIHNpZ25h..."
}
```

**Response — `201 Created`:**

```json
{
  "entry": {
    "id": "01JQXYZ1234567890ABCDEF",
    "sequence": 42,
    "suite_report": { "..." : "..." },
    "submitter_public_key": "MCowBQYDK2VwAyEA2b5y...",
    "submitter_signature": "dGhpcyBpcyBhIHNpZ25h...",
    "log_signature": "c2VydmVyIHNpZ25hdHVy...",
    "leaf_hash": "sha256:abcdef1234567890...",
    "timestamp": "2025-01-15T10:30:01Z"
  },
  "inclusion_proof": {
    "leaf_index": 42,
    "tree_size": 43,
    "hashes": [
      "sha256:1111111111111111...",
      "sha256:2222222222222222..."
    ]
  }
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 201 | Entry created and appended to the log |
| 400 | Invalid request body or malformed SuiteReport |
| 401 | Invalid or missing submitter ed25519 signature |
| 409 | Duplicate submission (same report already logged) |
| 503 | Server unable to append to log (temporary) |

**Example:**

```bash
curl -X POST https://ctn.openjobspec.org/v1/submissions \
  -H "Content-Type: application/json" \
  -d '{
    "suite_report": {
      "backend": "ojs-backend-redis",
      "version": "0.3.0",
      "conformance_level": 4,
      "total_tests": 256,
      "passed": 256,
      "failed": 0,
      "skipped": 0,
      "timestamp": "2025-01-15T10:30:00Z",
      "runner_version": "1.2.0"
    },
    "submitter_public_key": "MCowBQYDK2VwAyEA2b5y...",
    "submitter_signature": "dGhpcyBpcyBhIHNpZ25h..."
  }'
```

---

### 2. GET /v1/entries/{id}

Retrieve a logged entry together with its Merkle inclusion proof.

**Description:** Returns the full entry (SuiteReport, signatures, metadata) and
a Merkle inclusion proof that the caller can independently verify against the
current tree head.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Entry ID (ULID format) |

**Response — `200 OK`:**

```json
{
  "entry": {
    "id": "01JQXYZ1234567890ABCDEF",
    "sequence": 42,
    "suite_report": {
      "backend": "ojs-backend-redis",
      "version": "0.3.0",
      "conformance_level": 4,
      "total_tests": 256,
      "passed": 256,
      "failed": 0,
      "skipped": 0,
      "timestamp": "2025-01-15T10:30:00Z",
      "runner_version": "1.2.0"
    },
    "submitter_public_key": "MCowBQYDK2VwAyEA2b5y...",
    "submitter_signature": "dGhpcyBpcyBhIHNpZ25h...",
    "log_signature": "c2VydmVyIHNpZ25hdHVy...",
    "leaf_hash": "sha256:abcdef1234567890...",
    "timestamp": "2025-01-15T10:30:01Z"
  },
  "inclusion_proof": {
    "leaf_index": 42,
    "tree_size": 100,
    "hashes": [
      "sha256:1111111111111111...",
      "sha256:2222222222222222...",
      "sha256:3333333333333333..."
    ]
  },
  "witness_cosignatures": [
    {
      "witness_id": "witness-alpha",
      "public_key": "MCowBQYDK2VwAyEA7k9x...",
      "signature": "d2l0bmVzcyBjb3NpZ24...",
      "cosigned_at": "2025-01-15T10:30:05Z"
    }
  ]
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Entry found and returned with proof |
| 404 | Entry not found |

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/entries/01JQXYZ1234567890ABCDEF
```

---

### 3. GET /v1/log/head

Get the current Merkle tree head with witness cosignatures.

**Description:** Returns the latest Merkle root hash, tree size, the log
server's ed25519 signature over the root, and any witness cosignatures collected
so far. Clients use this to verify inclusion proofs.

**Response — `200 OK`:**

```json
{
  "tree_size": 100,
  "root_hash": "sha256:aabbccdd11223344...",
  "timestamp": "2025-01-15T10:31:00Z",
  "log_signature": "c2lnbmVkIGhlYWQ...",
  "log_public_key": "MCowBQYDK2VwAyEA9f3r...",
  "witness_cosignatures": [
    {
      "witness_id": "witness-alpha",
      "public_key": "MCowBQYDK2VwAyEA7k9x...",
      "signature": "d2l0bmVzcyBhbHBoYQ...",
      "cosigned_at": "2025-01-15T10:31:02Z"
    },
    {
      "witness_id": "witness-beta",
      "public_key": "MCowBQYDK2VwAyEBxQ2m...",
      "signature": "d2l0bmVzcyBiZXRh...",
      "cosigned_at": "2025-01-15T10:31:03Z"
    }
  ]
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Current log head returned |

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/log/head
```

---

### 4. GET /v1/registry

Convenience endpoint that returns a summary of all conformance results in the
log. Useful for dashboards and quick lookups without traversing individual
entries.

**Description:** Queries the log and returns the latest conformance status for
every backend that has at least one entry. Results are sorted by backend name.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | integer | — | Filter by minimum conformance level (0–4) |
| `limit` | integer | 100 | Maximum number of results |
| `offset` | integer | 0 | Pagination offset |

**Response — `200 OK`:**

```json
{
  "backends": [
    {
      "name": "ojs-backend-redis",
      "latest_version": "0.3.0",
      "conformance_level": 4,
      "total_entries": 12,
      "last_submitted": "2025-01-15T10:30:01Z",
      "latest_entry_id": "01JQXYZ1234567890ABCDEF"
    },
    {
      "name": "ojs-backend-postgres",
      "latest_version": "0.3.0",
      "conformance_level": 4,
      "total_entries": 8,
      "last_submitted": "2025-01-14T15:20:00Z",
      "latest_entry_id": "01JQWVU9876543210FEDCBA"
    }
  ],
  "total": 7,
  "limit": 100,
  "offset": 0
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Registry results returned |

**Example:**

```bash
curl "https://ctn.openjobspec.org/v1/registry?level=4"
```

---

### 5. GET /v1/registry/backends

List all backends that have at least one conformance entry in the log.

**Response — `200 OK`:**

```json
{
  "backends": [
    "ojs-backend-amqp",
    "ojs-backend-kafka",
    "ojs-backend-lite",
    "ojs-backend-nats",
    "ojs-backend-postgres",
    "ojs-backend-redis",
    "ojs-backend-sqs"
  ]
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Backend list returned |

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/registry/backends
```

---

### 6. GET /v1/registry/backends/{name}

Get the full conformance history for a specific backend.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Backend name (e.g., `ojs-backend-redis`) |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Maximum number of entries |
| `offset` | integer | 0 | Pagination offset |

**Response — `200 OK`:**

```json
{
  "backend": "ojs-backend-redis",
  "entries": [
    {
      "entry_id": "01JQXYZ1234567890ABCDEF",
      "version": "0.3.0",
      "conformance_level": 4,
      "total_tests": 256,
      "passed": 256,
      "failed": 0,
      "timestamp": "2025-01-15T10:30:01Z",
      "revoked": false
    },
    {
      "entry_id": "01JQABC0000000000000000",
      "version": "0.2.0",
      "conformance_level": 3,
      "total_tests": 200,
      "passed": 200,
      "failed": 0,
      "timestamp": "2024-12-01T08:00:00Z",
      "revoked": false
    }
  ],
  "total": 12,
  "limit": 50,
  "offset": 0
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Backend history returned |
| 404 | Backend not found in the registry |

**Example:**

```bash
curl "https://ctn.openjobspec.org/v1/registry/backends/ojs-backend-redis?limit=10"
```

---

### 7. GET /v1/badges/{backend}.svg

Generate an SVG conformance badge for a backend. Suitable for embedding in
README files.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `backend` | string | Backend name (e.g., `ojs-backend-redis`) |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `style` | string | `flat` | Badge style: `flat`, `flat-square`, `for-the-badge` |

**Response — `200 OK`:**

Returns an SVG image. Content-Type: `image/svg+xml`.

The badge displays:
- "OJS Conformance" label
- Level achieved (e.g., "L4") with a green/yellow/red color based on level

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Badge SVG returned |
| 404 | No conformance entries found for this backend |

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/badges/ojs-backend-redis.svg -o badge.svg
```

**Markdown embed:**

```markdown
![OJS Conformance](https://ctn.openjobspec.org/v1/badges/ojs-backend-redis.svg)
```

---

### 8. POST /v1/entries/{id}/witness

Submit a witness cosignature for an existing log entry.

**Description:** A registered witness calls this endpoint to cosign an entry
after independently verifying its inclusion proof and the submitter's signature.
The cosignature attests that the witness observed the entry at a specific tree
head.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Entry ID to cosign |

**Request Body:**

```json
{
  "witness_id": "witness-alpha",
  "tree_size": 100,
  "root_hash": "sha256:aabbccdd11223344...",
  "signature": "d2l0bmVzcyBjb3NpZ24...",
  "public_key": "MCowBQYDK2VwAyEA7k9x..."
}
```

**Response — `200 OK`:**

```json
{
  "entry_id": "01JQXYZ1234567890ABCDEF",
  "witness_id": "witness-alpha",
  "accepted": true,
  "cosigned_at": "2025-01-15T10:30:05Z"
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Cosignature accepted |
| 400 | Invalid cosignature or tree head mismatch |
| 401 | Witness not registered or invalid ed25519 signature |
| 404 | Entry not found |
| 409 | Witness already cosigned this entry |

**Example:**

```bash
curl -X POST https://ctn.openjobspec.org/v1/entries/01JQXYZ1234567890ABCDEF/witness \
  -H "Content-Type: application/json" \
  -d '{
    "witness_id": "witness-alpha",
    "tree_size": 100,
    "root_hash": "sha256:aabbccdd11223344...",
    "signature": "d2l0bmVzcyBjb3NpZ24...",
    "public_key": "MCowBQYDK2VwAyEA7k9x..."
  }'
```

---

### 9. POST /v1/entries/{id}/revoke

Publish a revocation marker for a previously logged entry.

**Description:** Revocation does **not** delete the entry (the log is
append-only). Instead, a new revocation entry is appended to the log that
references the original entry ID. Clients querying the registry will see the
entry marked as revoked. Only the original submitter (verified by ed25519
signature) can revoke an entry.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Entry ID to revoke |

**Request Body:**

```json
{
  "reason": "Test results were from an incorrect configuration.",
  "submitter_public_key": "MCowBQYDK2VwAyEA2b5y...",
  "submitter_signature": "cmV2b2tlIHNpZ25hdHVy..."
}
```

**Response — `200 OK`:**

```json
{
  "revocation_entry_id": "01JQZZZ9999999999999999",
  "revoked_entry_id": "01JQXYZ1234567890ABCDEF",
  "reason": "Test results were from an incorrect configuration.",
  "timestamp": "2025-01-15T12:00:00Z"
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Revocation marker published |
| 400 | Invalid request or missing reason |
| 401 | Signature does not match the original submitter |
| 404 | Entry not found |
| 409 | Entry already revoked |

**Example:**

```bash
curl -X POST https://ctn.openjobspec.org/v1/entries/01JQXYZ1234567890ABCDEF/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Test results were from an incorrect configuration.",
    "submitter_public_key": "MCowBQYDK2VwAyEA2b5y...",
    "submitter_signature": "cmV2b2tlIHNpZ25hdHVy..."
  }'
```

---

### 10. GET /v1/entries/{id}/status

Get the verification status of an entry, including signature validity, proof
status, witness coverage, and revocation state.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Entry ID |

**Response — `200 OK`:**

```json
{
  "entry_id": "01JQXYZ1234567890ABCDEF",
  "submitter_signature_valid": true,
  "log_signature_valid": true,
  "inclusion_proof_valid": true,
  "witness_cosignatures": 3,
  "required_cosignatures": 2,
  "fully_witnessed": true,
  "revoked": false,
  "revocation_entry_id": null
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Status returned |
| 404 | Entry not found |

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/entries/01JQXYZ1234567890ABCDEF/status
```

---

### 11. POST /v1/witnesses/register

Register a new witness with the CTN log server.

**Description:** Witnesses are independent parties that cosign log entries to
provide additional assurance that the log has not been tampered with. Each
witness is identified by a unique name and an ed25519 public key.

**Request Body:**

```json
{
  "witness_id": "witness-gamma",
  "public_key": "MCowBQYDK2VwAyECpQ8m...",
  "name": "ACME Corp Witness",
  "url": "https://witness.acme.example.com",
  "contact": "security@acme.example.com"
}
```

**Response — `201 Created`:**

```json
{
  "witness_id": "witness-gamma",
  "public_key": "MCowBQYDK2VwAyECpQ8m...",
  "name": "ACME Corp Witness",
  "registered_at": "2025-01-15T09:00:00Z"
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 201 | Witness registered |
| 400 | Invalid request (missing fields, bad key format) |
| 409 | Witness ID already registered |

**Example:**

```bash
curl -X POST https://ctn.openjobspec.org/v1/witnesses/register \
  -H "Content-Type: application/json" \
  -d '{
    "witness_id": "witness-gamma",
    "public_key": "MCowBQYDK2VwAyECpQ8m...",
    "name": "ACME Corp Witness",
    "url": "https://witness.acme.example.com",
    "contact": "security@acme.example.com"
  }'
```

---

### 12. GET /v1/witnesses

List all registered witnesses.

**Response — `200 OK`:**

```json
{
  "witnesses": [
    {
      "witness_id": "witness-alpha",
      "public_key": "MCowBQYDK2VwAyEA7k9x...",
      "name": "OpenJobSpec Foundation Witness",
      "url": "https://witness-alpha.openjobspec.org",
      "registered_at": "2025-01-01T00:00:00Z",
      "last_cosign_at": "2025-01-15T10:31:02Z",
      "total_cosignatures": 98
    },
    {
      "witness_id": "witness-beta",
      "public_key": "MCowBQYDK2VwAyEBxQ2m...",
      "name": "Community Witness",
      "url": "https://witness.community-infra.example.org",
      "registered_at": "2025-01-05T12:00:00Z",
      "last_cosign_at": "2025-01-15T10:31:03Z",
      "total_cosignatures": 85
    }
  ]
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Witness list returned |

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/witnesses
```

---

### 13. GET /v1/witnesses/{id}/stats

Get detailed statistics for a specific witness.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Witness ID |

**Response — `200 OK`:**

```json
{
  "witness_id": "witness-alpha",
  "name": "OpenJobSpec Foundation Witness",
  "public_key": "MCowBQYDK2VwAyEA7k9x...",
  "registered_at": "2025-01-01T00:00:00Z",
  "total_cosignatures": 98,
  "last_cosign_at": "2025-01-15T10:31:02Z",
  "avg_cosign_delay_ms": 3200,
  "uptime_30d_percent": 99.95,
  "entries_missed_30d": 2
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Witness stats returned |
| 404 | Witness not found |

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/witnesses/witness-alpha/stats
```

---

### 14. GET /v1/metrics

Prometheus metrics endpoint.

**Description:** Returns all server metrics in Prometheus exposition format.
This endpoint is intended for scraping by a Prometheus server and is not
authenticated.

**Response — `200 OK`:**

Content-Type: `text/plain; version=0.0.4; charset=utf-8`

```
# HELP ctn_log_entries_total Total number of entries in the log.
# TYPE ctn_log_entries_total counter
ctn_log_entries_total 100

# HELP ctn_merkle_tree_size Current number of leaves in the Merkle tree.
# TYPE ctn_merkle_tree_size gauge
ctn_merkle_tree_size 100

# HELP ctn_submission_duration_seconds Submission handling latency.
# TYPE ctn_submission_duration_seconds histogram
ctn_submission_duration_seconds_bucket{le="0.1"} 5
ctn_submission_duration_seconds_bucket{le="0.5"} 40
ctn_submission_duration_seconds_bucket{le="1"} 85
ctn_submission_duration_seconds_bucket{le="2"} 98
ctn_submission_duration_seconds_bucket{le="+Inf"} 100

# HELP ctn_http_requests_total Total HTTP requests by method and status.
# TYPE ctn_http_requests_total counter
ctn_http_requests_total{method="GET",path="/v1/entries",status="200"} 5000
ctn_http_requests_total{method="POST",path="/v1/submissions",status="201"} 100
```

**Example:**

```bash
curl https://ctn.openjobspec.org/v1/metrics
```

---

### 15. GET /healthz

Health check endpoint.

**Description:** Returns the server health status. A `200` response indicates
the server is healthy and ready to accept traffic. The response includes
component-level health for diagnostics.

**Response — `200 OK`:**

```json
{
  "status": "ok",
  "checks": {
    "log_writable": true,
    "merkle_consistent": true,
    "signing_key_available": true
  },
  "version": "0.1.0",
  "uptime_seconds": 86400
}
```

**Response — `503 Service Unavailable`:**

```json
{
  "status": "degraded",
  "checks": {
    "log_writable": false,
    "merkle_consistent": true,
    "signing_key_available": true
  },
  "error": "append-only log file is not writable"
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Healthy |
| 503 | One or more health checks failing |

**Example:**

```bash
curl https://ctn.openjobspec.org/healthz
```

---

## Error Format

All error responses use a consistent JSON structure:

```json
{
  "error": {
    "code": "INVALID_SIGNATURE",
    "message": "The submitter ed25519 signature does not match the provided public key.",
    "details": {}
  }
}
```

## Cryptographic Details

- **Signing algorithm:** Ed25519 (RFC 8032)
- **Hash function:** SHA-256 for Merkle tree leaf and interior nodes
- **Leaf hash:** `SHA256(0x00 || entry_bytes)` — the `0x00` prefix distinguishes
  leaves from interior nodes
- **Interior node hash:** `SHA256(0x01 || left_hash || right_hash)`
- **Public keys:** Base64-encoded SubjectPublicKeyInfo (SPKI) DER format
- **Signatures:** Base64-encoded raw ed25519 signatures (64 bytes)
