package main

import (
	"fmt"
	"io"
	"time"
)

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
