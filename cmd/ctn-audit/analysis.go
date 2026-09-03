package main

import (
	"crypto/ed25519"
	"sort"
	"time"
)

// Report is the JSON shape emitted by -json. It's also the schema the
// future Studio panel will consume; keep field names stable.
type Report struct {
	Endpoint        string                 `json:"endpoint"`
	GeneratedAt     time.Time              `json:"generated_at"`
	HeadSize        uint64                 `json:"head_size"`
	HeadSHA256      string                 `json:"head_sha256,omitempty"`
	EntriesAudited  int                    `json:"entries_audited"`
	SeqMin          uint64                 `json:"seq_min"`
	SeqMax          uint64                 `json:"seq_max"`
	SeqGaps         []uint64               `json:"seq_gaps,omitempty"`
	SeqDuplicates   []uint64               `json:"seq_duplicates,omitempty"`
	OldestEntry     *time.Time             `json:"oldest_entry,omitempty"`
	NewestEntry     *time.Time             `json:"newest_entry,omitempty"`
	SubmitterCounts map[string]int         `json:"submitter_counts"`
	WitnessCoverage WitnessCoverageSection `json:"witness_coverage"`
	Verification    VerificationSection    `json:"verification"`
	Failures        []EntryFailure         `json:"failures,omitempty"`
	Healthy         bool                   `json:"healthy"`
}

type WitnessCoverageSection struct {
	AtLeast1         int     `json:"at_least_1"`
	AtLeast2         int     `json:"at_least_2"`
	Coverage1Pct     float64 `json:"coverage_1_pct"`
	RequiredPct      float64 `json:"required_pct"`
	MeetsRequiredPct bool    `json:"meets_required_pct"`
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
