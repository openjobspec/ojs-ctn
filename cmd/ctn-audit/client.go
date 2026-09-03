package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Subset of the wire shapes from internal/store, duplicated here so this
// command stays a thin client (no internal package import; that path
// would couple the auditor to the server's storage layout).
type entry struct {
	EntryID             string               `json:"entry_id"`
	LoggedAt            time.Time            `json:"logged_at"`
	ReportSHA256        string               `json:"report_sha256"`
	Report              json.RawMessage      `json:"report"`
	SubmitterSignature  string               `json:"submitter_signature"`
	SubmitterKeyID      string               `json:"submitter_key_id"`
	SequenceNumber      uint64               `json:"sequence_number"`
	WitnessCosignatures []witnessCosignature `json:"witness_cosignatures,omitempty"`
}

type witnessCosignature struct {
	WitnessKeyID     string    `json:"witness_key_id"`
	WitnessSignature string    `json:"witness_signature"`
	CosignedAt       time.Time `json:"cosigned_at"`
}

type head struct {
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

func fetchHead(ctx context.Context, c *http.Client, endpoint string) (head, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/v1/log/head", nil)
	resp, err := c.Do(req)
	if err != nil {
		return head{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return head{}, fmt.Errorf("head: HTTP %d", resp.StatusCode)
	}
	var h head
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return head{}, err
	}
	return h, nil
}

// fetchTail iterates entries by sequence number, newest first, up to
// limit. The CTN P1 API exposes /v1/entries/<id>; sequence numbers are
// 1..size. We translate via the sequence-aware endpoint convention
// /v1/entries/seq:N (added in the same M5 slice). If the server
// doesn't support it we fall back to a 404 → skip so the auditor
// degrades gracefully on older servers.
func fetchTail(ctx context.Context, c *http.Client, endpoint string, size uint64, limit int) ([]entry, error) {
	if size == 0 {
		return nil, nil
	}
	want := uint64(limit)
	if want > size {
		want = size
	}
	out := make([]entry, 0, want)
	for i := uint64(0); i < want; i++ {
		seq := size - i
		url := fmt.Sprintf("%s/v1/entries/seq:%d", strings.TrimRight(endpoint, "/"), seq)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := c.Do(req)
		if err != nil {
			return out, err
		}
		if resp.StatusCode == 404 {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return out, fmt.Errorf("entry seq=%d: HTTP %d", seq, resp.StatusCode)
		}
		var e entry
		if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
			resp.Body.Close()
			return out, err
		}
		resp.Body.Close()
		out = append(out, e)
	}
	return out, nil
}
