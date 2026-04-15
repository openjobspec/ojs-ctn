# CTN Operational Runbook

This runbook covers day-to-day operations, monitoring, backup, and incident
response for the Conformance Transparency Network (CTN) log server.

---

## 1. Starting the Server

### Binary

```bash
# Minimal startup
./ctn-server \
  --listen :8080 \
  --log-file /var/lib/ctn/ledger.jsonl \
  --signing-key /etc/ctn/server.ed25519.key

# All flags
./ctn-server \
  --listen :8080 \
  --log-file /var/lib/ctn/ledger.jsonl \
  --signing-key /etc/ctn/server.ed25519.key \
  --public-key /etc/ctn/server.ed25519.pub \
  --witnesses-dir /etc/ctn/witnesses/ \
  --metrics-listen :9090 \
  --required-cosignatures 2 \
  --read-timeout 10s \
  --write-timeout 30s \
  --max-body-size 1048576
```

### Docker

```bash
docker run -d \
  --name ctn-server \
  -p 8080:8080 \
  -p 9090:9090 \
  -v /var/lib/ctn:/data \
  -v /etc/ctn:/etc/ctn:ro \
  ghcr.io/openjobspec/ctn-server:latest \
    --log-file /data/ledger.jsonl \
    --signing-key /etc/ctn/server.ed25519.key
```

### Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8080` | Address for the API server |
| `--log-file` | `ledger.jsonl` | Path to the append-only log file |
| `--signing-key` | — | Path to the server's ed25519 private key (required) |
| `--public-key` | — | Path to the server's ed25519 public key (derived from private key if omitted) |
| `--witnesses-dir` | — | Directory containing registered witness public keys |
| `--metrics-listen` | `:9090` | Address for the Prometheus metrics endpoint |
| `--required-cosignatures` | `1` | Minimum witness cosignatures before an entry is considered fully witnessed |
| `--read-timeout` | `10s` | HTTP read timeout |
| `--write-timeout` | `30s` | HTTP write timeout |
| `--max-body-size` | `1048576` | Maximum request body size in bytes (1 MiB default) |

### Key Generation

Generate an ed25519 key pair for the log server:

```bash
# Generate private key
openssl genpkey -algorithm ed25519 -out server.ed25519.key

# Extract public key
openssl pkey -in server.ed25519.key -pubout -out server.ed25519.pub
```

---

## 2. Monitoring

### Metrics Endpoint

The CTN server exposes Prometheus metrics at `/v1/metrics` (main port) and
optionally on a dedicated `--metrics-listen` port. Configure your Prometheus
instance to scrape this endpoint.

**Prometheus scrape config:**

```yaml
scrape_configs:
  - job_name: "ctn"
    static_configs:
      - targets: ["ctn-server:9090"]
    scrape_interval: 15s
```

### Key Metrics to Alert On

| Metric | Condition | Severity | Action |
|--------|-----------|----------|--------|
| `ctn_submission_duration_seconds` (p95) | > 2s for 5 min | Warning | Investigate I/O or load |
| `ctn_submission_duration_seconds` (p95) | > 5s for 5 min | Critical | Page on-call |
| `ctn_verification_duration_seconds` (p95) | > 200ms for 5 min | Warning | Check Merkle tree size, memory |
| `ctn_http_requests_total` (5xx rate) | > 1% for 5 min | Critical | Page on-call |
| `ctn_log_entries_total` | No increase in 24h (if submissions expected) | Warning | Check submission pipeline |
| `ctn_merkle_tree_size` | Diverges from `ctn_log_entries_total` | Critical | Possible corruption — see §6 |
| `ctn_witness_cosignatures_total` | No increase in 1h | Warning | Check witness connectivity |

### Alertmanager Rules (Example)

```yaml
groups:
  - name: ctn
    rules:
      - alert: CTNSubmissionLatencyHigh
        expr: histogram_quantile(0.95, rate(ctn_submission_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "CTN submission p95 latency exceeds 2s"

      - alert: CTNServerErrors
        expr: rate(ctn_http_requests_total{status=~"5.."}[5m]) / rate(ctn_http_requests_total[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "CTN server error rate exceeds 1%"

      - alert: CTNWitnessSilent
        expr: increase(ctn_witness_cosignatures_total[1h]) == 0
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "No witness cosignatures received in 1 hour"
```

### Health Check

Use the `/healthz` endpoint for liveness and readiness probes:

```bash
curl -sf http://localhost:8080/healthz | jq .status
```

For Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 15
readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 2
  periodSeconds: 5
```

---

## 3. Backup and Restore

### Source of Truth

The append-only log file (`ledger.jsonl`) is the sole source of truth. Each line
is a JSON object representing one log entry (submission, revocation, or witness
registration event). The Merkle tree is deterministically rebuilt from this file
on startup.

### Backup Strategy

1. **Continuous backup:** Use filesystem-level snapshots or a tool like
   `rsync --append` to continuously replicate `ledger.jsonl` to a secondary
   location. Because the file is append-only, incremental backups are safe and
   efficient.

   ```bash
   rsync --append /var/lib/ctn/ledger.jsonl backup-host:/backups/ctn/ledger.jsonl
   ```

2. **Periodic full backup:** Take a daily full copy with a checksum:

   ```bash
   cp /var/lib/ctn/ledger.jsonl /backups/ctn/ledger-$(date +%Y%m%d).jsonl
   sha256sum /backups/ctn/ledger-$(date +%Y%m%d).jsonl > /backups/ctn/ledger-$(date +%Y%m%d).sha256
   ```

3. **Offsite replication:** Push backups to object storage (S3, GCS) for
   disaster recovery:

   ```bash
   aws s3 cp /var/lib/ctn/ledger.jsonl s3://ctn-backups/ledger-$(date +%Y%m%d).jsonl
   ```

### Restore Procedure

1. Stop the CTN server.
2. Replace `ledger.jsonl` with the backup copy.
3. Verify the file integrity: `sha256sum ledger.jsonl`.
4. Start the server — it will rebuild the Merkle tree from the log file on
   startup.
5. Verify the tree head matches expectations: `curl http://localhost:8080/v1/log/head`.
6. Re-announce the tree head to witnesses so they can verify consistency.

> **Warning:** Restoring from a backup that is older than the current log will
> lose entries that were appended after the backup was taken. This is acceptable
> only in a disaster recovery scenario. Any lost entries should be re-submitted
> by their original submitters.

---

## 4. Witness Management

### Registering a New Witness

1. The witness operator generates an ed25519 key pair:

   ```bash
   openssl genpkey -algorithm ed25519 -out witness.ed25519.key
   openssl pkey -in witness.ed25519.key -pubout -out witness.ed25519.pub
   ```

2. Register the witness with the CTN server:

   ```bash
   curl -X POST http://localhost:8080/v1/witnesses/register \
     -H "Content-Type: application/json" \
     -d '{
       "witness_id": "witness-gamma",
       "public_key": "'$(base64 < witness.ed25519.pub)'",
       "name": "Gamma Witness",
       "url": "https://witness-gamma.example.com",
       "contact": "ops@example.com"
     }'
   ```

3. Optionally, place the witness public key in the `--witnesses-dir` directory
   for offline validation:

   ```bash
   cp witness.ed25519.pub /etc/ctn/witnesses/witness-gamma.pub
   ```

### Rotating a Witness Key

Witness key rotation is a two-phase process:

1. **Register new key:** Register a new witness entry with a new `witness_id`
   (e.g., `witness-gamma-v2`) and the new public key.
2. **Transition period:** Run both old and new witness instances concurrently.
   Both will cosign new entries.
3. **Decommission old key:** After all entries during the transition period are
   cosigned by the new witness, stop the old witness instance.
4. **Update documentation:** Record the rotation event and the new public key in
   the witness directory.

> **Note:** Old cosignatures remain valid because they were made with a key that
> was valid at the time. The append-only log preserves this history.

### Removing a Witness

Witnesses cannot be deleted from the log (the log is append-only). To
decommission a witness:

1. Stop the witness cosigning process.
2. Remove the witness public key from `--witnesses-dir`.
3. The witness will no longer appear in new cosignature sets but its historical
   cosignatures remain verifiable.

---

## 5. Troubleshooting

### Submission Failures

**Symptom:** `POST /v1/submissions` returns `401 Unauthorized`.

**Cause:** The submitter's ed25519 signature does not verify against the
provided public key.

**Resolution:**
1. Verify the submitter is signing the exact bytes of the `suite_report` JSON
   (canonicalized, no extra whitespace).
2. Confirm the public key is base64-encoded SPKI DER format.
3. Test signature verification locally:
   ```bash
   echo -n '<suite_report_json>' | openssl pkeyutl -verify \
     -pubin -inkey submitter.pub -sigfile signature.bin
   ```

---

**Symptom:** `POST /v1/submissions` returns `503 Service Unavailable`.

**Cause:** The server cannot append to `ledger.jsonl`.

**Resolution:**
1. Check file permissions: `ls -la /var/lib/ctn/ledger.jsonl`.
2. Check disk space: `df -h /var/lib/ctn/`.
3. Check if the file is locked by another process: `lsof /var/lib/ctn/ledger.jsonl`.
4. Review server logs for I/O errors.

---

### Merkle Proof Verification Errors

**Symptom:** A client cannot verify an inclusion proof returned by
`GET /v1/entries/{id}`.

**Possible causes:**
1. **Stale tree head:** The client is verifying against an outdated tree head.
   Fetch the latest head with `GET /v1/log/head` and retry.
2. **Incorrect hash computation:** Ensure the client uses the correct leaf hash
   formula: `SHA256(0x00 || entry_bytes)`, and interior node formula:
   `SHA256(0x01 || left || right)`.
3. **Proof for wrong tree size:** The inclusion proof is bound to a specific
   `tree_size`. Verify that the `tree_size` in the proof matches the tree head
   being checked against.

**Diagnostic steps:**
```bash
# Fetch the entry and proof
curl -s http://localhost:8080/v1/entries/01JQXYZ1234567890ABCDEF | jq .

# Fetch the current tree head
curl -s http://localhost:8080/v1/log/head | jq .

# Compare tree_size values
```

---

### Witness Sync Issues

**Symptom:** `ctn_witness_cosignatures_total` is not increasing; entries lack
cosignatures.

**Possible causes:**
1. **Witness is down:** Check the witness service health at its URL.
2. **Network issues:** The witness cannot reach the CTN server.
3. **Clock skew:** Large clock differences between the witness and CTN server
   can cause signature verification to fail if timestamps are validated.
4. **Key mismatch:** The witness is signing with a key that does not match the
   registered public key.

**Resolution:**
1. Check witness stats: `curl http://localhost:8080/v1/witnesses/witness-alpha/stats`.
2. Check network connectivity from the witness to the CTN server.
3. Review witness-side logs for signing errors.
4. If the witness key was rotated without re-registering, follow the key
   rotation procedure in §4.

---

## 6. Incident Response: Log Integrity Issues

### Hash Chain Break

**Symptom:** The server reports a Merkle tree inconsistency on startup, or the
`/healthz` endpoint shows `merkle_consistent: false`.

**Severity:** Critical — this indicates potential tampering or data corruption.

**Immediate actions:**

1. **Do NOT restart the server.** Preserve the current state for forensic
   analysis.
2. **Alert the incident response team.** This is a P0 incident.
3. **Take a forensic copy of the log file:**
   ```bash
   cp /var/lib/ctn/ledger.jsonl /var/lib/ctn/ledger.forensic.$(date +%s).jsonl
   sha256sum /var/lib/ctn/ledger.forensic.*.jsonl
   ```
4. **Compare against the latest known-good backup:**
   ```bash
   diff <(head -n $(wc -l < /backups/ctn/ledger-latest.jsonl) /var/lib/ctn/ledger.jsonl) \
        /backups/ctn/ledger-latest.jsonl
   ```
5. **Identify the divergence point:** Find the first line where the current log
   differs from the backup. Entries after this point are suspect.

**Recovery:**

- If the divergence is at the tail (appended corrupt entries), truncate the log
  to the last known-good entry and restart.
- If entries in the middle were modified, this indicates tampering. Restore from
  the last backup that predates the modification and investigate the root cause.
- After recovery, the tree head will change. Notify all witnesses and
  consumers so they can re-verify their local state.

### Compromised Server Signing Key

**Symptom:** Unauthorized entries appear in the log, or the private key file was
accessed by an unauthorized party.

**Immediate actions:**

1. **Shut down the CTN server** to prevent further entries.
2. **Rotate the signing key:**
   ```bash
   openssl genpkey -algorithm ed25519 -out server.ed25519.key.new
   openssl pkey -in server.ed25519.key.new -pubout -out server.ed25519.pub.new
   mv server.ed25519.key.new /etc/ctn/server.ed25519.key
   mv server.ed25519.pub.new /etc/ctn/server.ed25519.pub
   ```
3. **Audit the log:** Review all entries signed with the compromised key.
   Entries that were also witness-cosigned are trustworthy (the attacker would
   need to compromise witnesses too). Entries without cosignatures during the
   compromise window should be flagged for re-verification.
4. **Publish the new public key** to all consumers and witnesses.
5. **Restart the server** with the new key.

### Compromised Witness Key

**Severity:** Medium — a single compromised witness does not break log
integrity because entries require the log server signature and multiple witness
cosignatures.

**Actions:**

1. Decommission the compromised witness (see §4).
2. Register a replacement witness with a new key.
3. Review entries that were cosigned *only* by the compromised witness — these
   entries still have the log server's signature and are not invalidated, but
   they lose one layer of assurance.
4. Notify consumers to update their trusted witness list.
