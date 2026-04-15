package metrics

import (
	"sync"
	"testing"
)

func TestNewCounters(t *testing.T) {
	c := NewCounters()
	snap := c.Snapshot()
	for k, v := range snap {
		if v != 0 {
			t.Errorf("expected %s to be 0, got %d", k, v)
		}
	}
}

func TestIncSubmissions(t *testing.T) {
	c := NewCounters()
	c.IncSubmissions()
	c.IncSubmissions()
	snap := c.Snapshot()
	if snap["submissions"] != 2 {
		t.Errorf("expected submissions=2, got %d", snap["submissions"])
	}
}

func TestIncQueries(t *testing.T) {
	c := NewCounters()
	c.IncQueries()
	snap := c.Snapshot()
	if snap["queries"] != 1 {
		t.Errorf("expected queries=1, got %d", snap["queries"])
	}
}

func TestIncBadges(t *testing.T) {
	c := NewCounters()
	c.IncBadges()
	c.IncBadges()
	c.IncBadges()
	snap := c.Snapshot()
	if snap["badges"] != 3 {
		t.Errorf("expected badges=3, got %d", snap["badges"])
	}
}

func TestIncWitnesses(t *testing.T) {
	c := NewCounters()
	c.IncWitnesses()
	snap := c.Snapshot()
	if snap["witnesses"] != 1 {
		t.Errorf("expected witnesses=1, got %d", snap["witnesses"])
	}
}

func TestIncErrors(t *testing.T) {
	c := NewCounters()
	c.IncErrors()
	snap := c.Snapshot()
	if snap["errors"] != 1 {
		t.Errorf("expected errors=1, got %d", snap["errors"])
	}
}

func TestSnapshotIsolation(t *testing.T) {
	c := NewCounters()
	c.IncSubmissions()
	snap := c.Snapshot()
	c.IncSubmissions()
	if snap["submissions"] != 1 {
		t.Errorf("snapshot should be isolated: expected 1, got %d", snap["submissions"])
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := NewCounters()
	var wg sync.WaitGroup
	n := 100
	wg.Add(n * 5)
	for i := 0; i < n; i++ {
		go func() { defer wg.Done(); c.IncSubmissions() }()
		go func() { defer wg.Done(); c.IncQueries() }()
		go func() { defer wg.Done(); c.IncBadges() }()
		go func() { defer wg.Done(); c.IncWitnesses() }()
		go func() { defer wg.Done(); c.IncErrors() }()
	}
	wg.Wait()
	snap := c.Snapshot()
	for k, v := range snap {
		if v != int64(n) {
			t.Errorf("expected %s=%d, got %d", k, n, v)
		}
	}
}
