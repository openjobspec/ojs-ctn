// Package metrics provides lightweight Prometheus-style in-memory
// counters for the CTN API server. No external dependencies — the
// counters are plain atomic int64s. P2 will bridge these to a real
// Prometheus registry via the /metrics endpoint.
package metrics

import (
	"sync/atomic"
)

// Counters tracks request-level counters for the CTN HTTP surface.
type Counters struct {
	submissions int64
	queries     int64
	badges      int64
	witnesses   int64
	errors      int64
}

// NewCounters creates a zeroed counter set.
func NewCounters() *Counters {
	return &Counters{}
}

// IncSubmissions increments the submissions counter.
func (c *Counters) IncSubmissions() { atomic.AddInt64(&c.submissions, 1) }

// IncQueries increments the queries counter.
func (c *Counters) IncQueries() { atomic.AddInt64(&c.queries, 1) }

// IncBadges increments the badges counter.
func (c *Counters) IncBadges() { atomic.AddInt64(&c.badges, 1) }

// IncWitnesses increments the witnesses counter.
func (c *Counters) IncWitnesses() { atomic.AddInt64(&c.witnesses, 1) }

// IncErrors increments the errors counter.
func (c *Counters) IncErrors() { atomic.AddInt64(&c.errors, 1) }

// Snapshot returns a point-in-time copy of all counters as a map.
func (c *Counters) Snapshot() map[string]int64 {
	return map[string]int64{
		"submissions": atomic.LoadInt64(&c.submissions),
		"queries":     atomic.LoadInt64(&c.queries),
		"badges":      atomic.LoadInt64(&c.badges),
		"witnesses":   atomic.LoadInt64(&c.witnesses),
		"errors":      atomic.LoadInt64(&c.errors),
	}
}
