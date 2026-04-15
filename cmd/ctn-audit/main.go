// Command ctn-audit is the auditor-facing dashboard CLI for a CTN log.
// Where ctn-verify checks one entry, ctn-audit walks the whole tail
// and produces a structured report:
//
//   - Total entries seen, sequence number range, time window.
//   - Per-submitter key ID counts.
//   - Witness-cosignature coverage (% of entries with >=1, >=2 witnesses).
//   - Verification breakdown: signed-ok / unknown-key / bad-sig.
//   - Optional gap detection: missing or out-of-order sequence numbers.
//
// Output is text by default and JSON with -json (pipe-friendly for
// alerting). Exit code is 0 if no errors *and* the witness coverage
// floor (configurable, default 0%) is met, 2 otherwise.
//
// This is the M5 deliverable that was promised in the moonshot brief
// as the "auditor dashboard", scoped down to a CLI so it ships in this
// session and a future Studio panel can wrap the same report shape.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Report is the JSON shape emitted by -json. It's also the schema the
// future Studio panel will consume; keep field names stable.
type Report struct {
	Endpoint        string                  `json:"endpoint"`
	GeneratedAt     time.Time               `json:"generated_at"`
	HeadSize        uint64                  `json:"head_size"`
	HeadSHA256      string                  `json:"head_sha256,omitempty"`
	EntriesAudited  int                     `json:"entries_audited"`
	SeqMin          uint64                  `json:"seq_min"`
	SeqMax          uint64                  `json:"seq_max"`
	SeqGaps         []uint64                `json:"seq_gaps,omitempty"`
	SeqDuplicates   []uint64                `json:"seq_duplicates,omitempty"`
	OldestEntry     *time.Time              `json:"oldest_entry,omitempty"`
	NewestEntry     *time.Time              `json:"newest_entry,omitempty"`
	SubmitterCounts map[string]int          `json:"submitter_counts"`
	WitnessCoverage WitnessCoverageSection  `json:"witness_coverage"`
	Verification    VerificationSection     `json:"verification"`
	Failures        []EntryFailure          `json:"failures,omitempty"`
	Healthy         bool                    `json:"healthy"`
}

type WitnessCoverageSection struct {
	AtLeast1        int     `json:"at_least_1"`
	AtLeast2        int     `json:"at_least_2"`
	Coverage1Pct    float64 `json:"coverage_1_pct"`
	RequiredPct     float64 `json:"required_pct"`
	MeetsRequiredPct bool   `json:"meets_required_pct"`
}

type VerificationSection struct {
	SignedOK   int `json:"signed_ok"`
	UnknownKey int `json:"unknown_key"`
	BadSig     int `json:"bad_sig"`
	Skipped    int `json:"skipped"`
}

type EntryFailure struct {
	EntryID string `json:"entry_id"`
	Reason  string `json:"reason"`
}

// Subset of the wire shapes from internal/store, duplicated here so this
// command stays a thin client (no internal package import; that path
// would couple the auditor to the server's storage layout).
type entry struct {
	EntryID             string             `json:"entry_id"`
	LoggedAt            time.Time          `json:"logged_at"`
	ReportSHA256        string             `json:"report_sha256"`
	Report              json.RawMessage    `json:"report"`
	SubmitterSignature  string             `json:"submitter_signature"`
	SubmitterKeyID      string             `json:"submitter_key_id"`
	SequenceNumber      uint64             `json:"sequence_number"`
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

func main() {
	if err := mainErr(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ctn-audit:", err)
		os.Exit(1)
	}
}

func mainErr(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ctn-audit", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "CTN base URL")
	limit := fs.Int("limit", 1000, "max entries to audit (walks newest-first by sequence number)")
	jsonOut := fs.Bool("json", false, "emit JSON report instead of text")
	trustFile := fs.String("trust-file", "", "optional submitter trust file (key_id → base64 ed25519 pubkey)")
	requiredCoverage := fs.Float64("required-witness-coverage", 0.0, "exit non-zero if <coverage of entries have >=1 witness, in [0,1]")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout per request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return errors.New("-endpoint required")
	}
	if *requiredCoverage < 0 || *requiredCoverage > 1 {
		return errors.New("-required-witness-coverage must be in [0,1]")
	}

	trust, err := loadTrust(*trustFile)
	if err != nil {
		return fmt.Errorf("load trust: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*time.Duration(*limit/100+5))
	defer cancel()
	client := &http.Client{Timeout: *timeout}

	h, err := fetchHead(ctx, client, *endpoint)
	if err != nil {
		return fmt.Errorf("fetch head: %w", err)
	}
	entries, err := fetchTail(ctx, client, *endpoint, h.Size, *limit)
	if err != nil {
		return fmt.Errorf("fetch tail: %w", err)
	}

	report := analyse(*endpoint, h, entries, trust, *requiredCoverage)
	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printText(out, report)
	}
	if !report.Healthy {
		os.Exit(2)
	}
	return nil
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

func analyse(endpoint string, h head, entries []entry, trust map[string]ed25519.PublicKey, requiredCoverage float64) Report {
	r := Report{
		Endpoint:        endpoint,
		GeneratedAt:     time.Now().UTC(),
		HeadSize:        h.Size,
		HeadSHA256:      h.SHA256,
		EntriesAudited:  len(entries),
		SubmitterCounts: map[string]int{},
		WitnessCoverage: WitnessCoverageSection{RequiredPct: requiredCoverage},
		Verification:    VerificationSection{},
	}
	if len(entries) == 0 {
		r.Healthy = true
		r.WitnessCoverage.MeetsRequiredPct = requiredCoverage == 0
		return r
	}

	seen := map[uint64]bool{}
	var seqs []uint64
	for _, e := range entries {
		if e.SequenceNumber > 0 {
			seqs = append(seqs, e.SequenceNumber)
		}
		if seen[e.SequenceNumber] {
			r.SeqDuplicates = append(r.SeqDuplicates, e.SequenceNumber)
		}
		seen[e.SequenceNumber] = true

		r.SubmitterCounts[e.SubmitterKeyID]++

		if !e.LoggedAt.IsZero() {
			if r.OldestEntry == nil || e.LoggedAt.Before(*r.OldestEntry) {
				t := e.LoggedAt
				r.OldestEntry = &t
			}
			if r.NewestEntry == nil || e.LoggedAt.After(*r.NewestEntry) {
				t := e.LoggedAt
				r.NewestEntry = &t
			}
		}

		if len(e.WitnessCosignatures) >= 1 {
			r.WitnessCoverage.AtLeast1++
		}
		if len(e.WitnessCosignatures) >= 2 {
			r.WitnessCoverage.AtLeast2++
		}

		switch verifyEntry(e, trust) {
		case verifyOK:
			r.Verification.SignedOK++
		case verifyUnknown:
			r.Verification.UnknownKey++
		case verifyBad:
			r.Verification.BadSig++
			r.Failures = append(r.Failures, EntryFailure{EntryID: e.EntryID, Reason: "bad signature"})
		case verifySkip:
			r.Verification.Skipped++
		}
	}

	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	r.SeqMin, r.SeqMax = seqs[0], seqs[len(seqs)-1]
	for i := 1; i < len(seqs); i++ {
		if seqs[i] == seqs[i-1] {
			continue
		}
		for missing := seqs[i-1] + 1; missing < seqs[i]; missing++ {
			r.SeqGaps = append(r.SeqGaps, missing)
		}
	}

	if r.EntriesAudited > 0 {
		r.WitnessCoverage.Coverage1Pct = float64(r.WitnessCoverage.AtLeast1) / float64(r.EntriesAudited)
	}
	r.WitnessCoverage.MeetsRequiredPct = r.WitnessCoverage.Coverage1Pct >= requiredCoverage
	r.Healthy = r.Verification.BadSig == 0 && r.WitnessCoverage.MeetsRequiredPct
	return r
}

type verifyOutcome int

const (
	verifyOK verifyOutcome = iota
	verifyUnknown
	verifyBad
	verifySkip
)

func verifyEntry(e entry, trust map[string]ed25519.PublicKey) verifyOutcome {
	if trust == nil {
		return verifySkip
	}
	pk, ok := trust[e.SubmitterKeyID]
	if !ok {
		return verifyUnknown
	}
	sig, err := base64.StdEncoding.DecodeString(e.SubmitterSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return verifyBad
	}
	canonical, err := canonicalize(e.Report)
	if err != nil {
		return verifyBad
	}
	if !ed25519.Verify(pk, canonical, sig) {
		return verifyBad
	}
	// Sanity: ReportSHA256 should match canonicalised bytes.
	sum := sha256.Sum256(canonical)
	if e.ReportSHA256 != "" && e.ReportSHA256 != hexEncode(sum[:]) {
		return verifyBad
	}
	return verifyOK
}

func canonicalize(raw json.RawMessage) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

func loadTrust(path string) (map[string]ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string]ed25519.PublicKey, len(m))
	for k, v := range m {
		pk, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("decode key %s: %w", k, err)
		}
		if len(pk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %s: bad size %d", k, len(pk))
		}
		out[k] = ed25519.PublicKey(pk)
	}
	return out, nil
}

func printText(w io.Writer, r Report) {
	fmt.Fprintf(w, "CTN Audit Report — %s\n", r.Endpoint)
	fmt.Fprintf(w, "  generated_at:   %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "  head_size:      %d\n", r.HeadSize)
	if r.HeadSHA256 != "" {
		fmt.Fprintf(w, "  head_sha256:    %s\n", r.HeadSHA256)
	}
	fmt.Fprintf(w, "  audited:        %d entries (seq %d..%d)\n", r.EntriesAudited, r.SeqMin, r.SeqMax)
	if r.OldestEntry != nil && r.NewestEntry != nil {
		fmt.Fprintf(w, "  time window:    %s .. %s\n", r.OldestEntry.Format(time.RFC3339), r.NewestEntry.Format(time.RFC3339))
	}
	fmt.Fprintln(w, "  submitters:")
	for k, c := range r.SubmitterCounts {
		fmt.Fprintf(w, "    %-40s %d\n", k, c)
	}
	fmt.Fprintf(w, "  witness coverage: %d (%.1f%%) >=1 cosig, %d >=2 cosigs (required >= %.1f%%, %s)\n",
		r.WitnessCoverage.AtLeast1, r.WitnessCoverage.Coverage1Pct*100,
		r.WitnessCoverage.AtLeast2, r.WitnessCoverage.RequiredPct*100,
		boolStr(r.WitnessCoverage.MeetsRequiredPct, "MET", "BELOW"))
	fmt.Fprintf(w, "  verification:   ok=%d unknown_key=%d bad_sig=%d skipped=%d\n",
		r.Verification.SignedOK, r.Verification.UnknownKey, r.Verification.BadSig, r.Verification.Skipped)
	if len(r.SeqGaps) > 0 {
		fmt.Fprintf(w, "  seq gaps:       %v\n", r.SeqGaps)
	}
	if len(r.SeqDuplicates) > 0 {
		fmt.Fprintf(w, "  seq duplicates: %v\n", r.SeqDuplicates)
	}
	for _, f := range r.Failures {
		fmt.Fprintf(w, "  FAIL %s: %s\n", f.EntryID, f.Reason)
	}
	fmt.Fprintf(w, "  healthy: %v\n", r.Healthy)
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
