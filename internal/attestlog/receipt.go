// Package attestlog provides receipt submission to the CTN transparency log
// for the Verifiable Compute pipeline (M1/P3).
//
// ReceiptSubmitter converts attestation receipts into CTN log entries,
// ensuring durable timestamping and ordering for downstream verification.
package attestlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Receipt contains the attestation data to submit to the CTN log.
type Receipt struct {
	// JobID is the OJS job identifier that was attested.
	JobID string `json:"job_id"`
	// ArgsHash is the SHA-256 hex digest of the job arguments.
	ArgsHash string `json:"args_hash"`
	// ResultHash is the SHA-256 hex digest of the job result.
	ResultHash string `json:"result_hash"`
	// Quote is the raw TEE/software attestation evidence.
	Quote json.RawMessage `json:"quote"`
	// Signature is the hex-encoded signature over the attestation.
	Signature string `json:"signature"`
	// KeyID identifies the signing key.
	KeyID string `json:"key_id"`
}

// SubmitResult contains the identifiers returned by the CTN log after
// a successful receipt submission.
type SubmitResult struct {
	// EntryID is the unique identifier of the CTN log entry.
	EntryID string `json:"entry_id"`
	// ReportSHA256 is the SHA-256 hex digest of the canonical report.
	ReportSHA256 string `json:"report_sha256"`
}

// ReceiptSubmitter submits attestation receipts to the CTN log.
type ReceiptSubmitter struct {
	ctnEndpoint string
	httpClient  *http.Client
}

// NewReceiptSubmitter creates a new ReceiptSubmitter pointed at the given
// CTN endpoint. The endpoint should be the base URL of the CTN service
// (e.g. "http://localhost:9090").
func NewReceiptSubmitter(ctnEndpoint string) *ReceiptSubmitter {
	return &ReceiptSubmitter{
		ctnEndpoint: ctnEndpoint,
		httpClient:  http.DefaultClient,
	}
}

// WithHTTPClient sets a custom HTTP client for the submitter.
func (s *ReceiptSubmitter) WithHTTPClient(c *http.Client) *ReceiptSubmitter {
	s.httpClient = c
	return s
}

// Submit sends an attestation receipt to the CTN log and returns the
// resulting entry identifiers.
func (s *ReceiptSubmitter) Submit(ctx context.Context, receipt Receipt) (*SubmitResult, error) {
	if receipt.JobID == "" {
		return nil, fmt.Errorf("attestlog: job_id required")
	}
	if receipt.ArgsHash == "" {
		return nil, fmt.Errorf("attestlog: args_hash required")
	}
	if receipt.Signature == "" {
		return nil, fmt.Errorf("attestlog: signature required")
	}
	if receipt.KeyID == "" {
		return nil, fmt.Errorf("attestlog: key_id required")
	}

	body, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("attestlog: marshal receipt: %w", err)
	}

	url := s.ctnEndpoint + "/v1/submissions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("attestlog: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attestlog: submit request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("attestlog: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var result SubmitResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("attestlog: decode response: %w", err)
	}

	return &result, nil
}
