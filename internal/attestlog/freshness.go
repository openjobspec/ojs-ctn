package attestlog

import (
	"time"

	"github.com/openjobspec/ojs-ctn/internal/store"
)

type freshnessPolicy struct {
	maxAge time.Duration
}

func newFreshnessPolicy(config DecayConfig) freshnessPolicy {
	maxAge := config.MaxAge
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	return freshnessPolicy{maxAge: maxAge}
}

func (p freshnessPolicy) classify(age time.Duration) AttestationStatus {
	if age > p.maxAge {
		return Outdated
	}
	return Active
}

func (sc *StatusChecker) checkAt(entry *store.Entry, now time.Time) StatusResult {
	revoked, reason := sc.revocation(entry.EntryID)
	if revoked {
		return revokedStatusAt(entry, now, reason)
	}
	return freshnessStatusAt(entry, now, newFreshnessPolicy(sc.Config))
}

func (sc *StatusChecker) revocation(entryID string) (bool, string) {
	if sc.Revocations == nil {
		return false, ""
	}
	return sc.Revocations.IsRevoked(entryID)
}

func revokedStatusAt(entry *store.Entry, now time.Time, reason string) StatusResult {
	age := now.Sub(entry.LoggedAt)
	return StatusResult{
		EntryID: entry.EntryID,
		Status:  Revoked,
		Reason:  reason,
		Age:     age.Truncate(time.Second).String(),
	}
}

func freshnessStatusAt(entry *store.Entry, now time.Time, policy freshnessPolicy) StatusResult {
	age := now.Sub(entry.LoggedAt)
	return StatusResult{
		EntryID: entry.EntryID,
		Status:  policy.classify(age),
		Age:     age.Truncate(time.Second).String(),
	}
}
