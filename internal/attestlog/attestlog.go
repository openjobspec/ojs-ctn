// Package attestlog adapts an ext_attest evidence document
// (RFC-0010-ext-attest.md) into a CTN store.Submission so the same log
// pipeline that records witness cosignatures (M5) also records job
// attestations (M1/P3). This is the Verifiable Compute → Transparency
// Network bridge listed as a P3 deliverable in the moonshot brief.
//
// Wire flow:
//
//	(ext_attest evidence JSON, signed by partner) ───▶ Submit() ───▶
//	  store.Submission{
//	    Report:             canonical(report wrapper),
//	    SubmitterSignature: evidence.signature,
//	    SubmitterKeyID:     evidence.key_id,
//	  } ───▶ POST /v1/submissions ───▶ CTN entry
//
// The log entry is now durably timestamped, ordered, and (once a
// witness cosignature attaches) externally endorsed — exactly the
// guarantees Verifiable Compute needs for downstream attestation
// verification.
//
// Why a separate report wrapper rather than POSTing the raw evidence?
//
//   - The CTN log indexes by ReportSHA256 over the .Report field; we
//     want that hash to cover the *attested computation*, not the
//     ed25519 signature bytes (which would change every re-sign).
//   - The wrapper carries minimal provenance fields the CTN auditor
//     surfaces in its inclusion-proof view (key id, alg, type,
//     digests, signed_at).
package attestlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openjobspec/ojs-ctn/internal/sigalg"
	"github.com/openjobspec/ojs-ctn/internal/store"
)

// Evidence mirrors the ext_attest evidence wire shape. We duplicate
// rather than import from ojs-codec-server to keep the CTN module
// dependency-free of the codec server (per ARCHITECTURE.md §"module
// boundaries"). RFC-0010 is the contract that keeps these in sync.
type Evidence struct {
	Version      int    `json:"v"`
	Algorithm    string `json:"alg"`
	Type         string `json:"type"`
	KeyID        string `json:"key_id"`
	InputDigest  string `json:"input_digest"`
	OutputDigest string `json:"output_digest,omitempty"`
	Document     string `json:"document,omitempty"`
	Signature    string `json:"signature"`
	SignedAt     string `json:"signed_at"`
}

// Report is the canonical "what was attested" wrapper that goes into
// CTN as Submission.Report. Reordering of any field MUST change the
// SHA-256 deterministically, so encoder uses sorted keys (json default
// in Go is field-declaration order; we accept that and freeze the
// declaration order here as part of the wire contract).
type Report struct {
	Version      int    `json:"v"`
	Type         string `json:"type"`
	Algorithm    string `json:"alg"`
	KeyID        string `json:"key_id"`
	InputDigest  string `json:"input_digest"`
	OutputDigest string `json:"output_digest,omitempty"`
	Document     string `json:"document,omitempty"`
	SignedAt     string `json:"signed_at"`
}

// ToSubmission converts e into a CTN store.Submission. The submission's
// SubmitterSignature carries e.Signature verbatim (so a verifier can
// check it against the canonical report hash), and the key id flows
// through unchanged.
//
// ToSubmission validates Evidence structurally; it does NOT verify the
// signature. The CTN ledger is content-addressing only, and signature
// verification happens on read by ojs-attest verify or any compatible
// implementation. We do however cross-check the algorithm against the
// sigalg registry so an unknown alg is rejected at submission time
// (else the entry would be unverifiable forever).
func ToSubmission(e Evidence) (store.Submission, error) {
	if err := e.Validate(); err != nil {
		return store.Submission{}, err
	}
	report := Report{
		Version:      e.Version,
		Type:         e.Type,
		Algorithm:    e.Algorithm,
		KeyID:        e.KeyID,
		InputDigest:  e.InputDigest,
		OutputDigest: e.OutputDigest,
		Document:     e.Document,
		SignedAt:     e.SignedAt,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return store.Submission{}, fmt.Errorf("attestlog: marshal report: %w", err)
	}
	return store.Submission{
		Report:             json.RawMessage(raw),
		SubmitterSignature: e.Signature,
		SubmitterKeyID:     e.KeyID,
	}, nil
}

// ReportHash returns the SHA-256 hex of the canonical report bytes.
// Useful for clients that want to pre-compute the expected entry id
// before submission, and for tests.
func ReportHash(e Evidence) (string, error) {
	sub, err := ToSubmission(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(sub.Report)
	return hex.EncodeToString(sum[:]), nil
}

// Validate enforces the structural rules from RFC-0010:
//
//   - Version must be 1 (the only published wire revision).
//   - Algorithm must be a registered sigalg.
//   - Type must be a known attestation kind.
//   - InputDigest, KeyID, Signature, SignedAt are required.
//   - SignedAt must parse as RFC 3339.
//   - All digest fields, when present, must be hex strings of length 64
//     (sha256) so we don't silently accept truncated hashes.
func (e Evidence) Validate() error {
	if e.Version != 1 {
		return fmt.Errorf("attestlog: unsupported evidence version %d", e.Version)
	}
	if _, err := sigalg.Lookup(sigalg.Algorithm(e.Algorithm)); err != nil {
		return fmt.Errorf("attestlog: %w", err)
	}
	if !knownType(e.Type) {
		return fmt.Errorf("attestlog: unknown evidence type %q", e.Type)
	}
	if strings.TrimSpace(e.KeyID) == "" {
		return errors.New("attestlog: key_id required")
	}
	if strings.TrimSpace(e.Signature) == "" {
		return errors.New("attestlog: signature required")
	}
	if err := requireSHA256Hex("input_digest", e.InputDigest); err != nil {
		return err
	}
	if e.OutputDigest != "" {
		if err := requireSHA256Hex("output_digest", e.OutputDigest); err != nil {
			return err
		}
	}
	if _, err := time.Parse(time.RFC3339, e.SignedAt); err != nil {
		return fmt.Errorf("attestlog: signed_at not RFC3339: %w", err)
	}
	return nil
}

func knownType(t string) bool {
	switch t {
	case "signature-only", "aws-nitro", "intel-tdx", "amd-sev-snp":
		return true
	}
	return false
}

func requireSHA256Hex(field, v string) error {
	if v == "" {
		return fmt.Errorf("attestlog: %s required", field)
	}
	if len(v) != 64 {
		return fmt.Errorf("attestlog: %s must be 32-byte sha256 hex (got len %d)", field, len(v))
	}
	if _, err := hex.DecodeString(v); err != nil {
		return fmt.Errorf("attestlog: %s not hex: %w", field, err)
	}
	return nil
}
