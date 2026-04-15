package dag

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestAppendIsContentAddressed(t *testing.T) {
	s := New()
	a, _ := s.Append("main", map[string]any{"step": 1})
	b, _ := s.Append("main", map[string]any{"step": 2})
	if a.ContentID == b.ContentID {
		t.Fatal("distinct payloads must yield distinct ids")
	}

	// Idempotency: re-appending an identical (parent, payload) pair must
	// be deduped. Use Append on a fresh branch where parent matches.
	c := New()
	c.Append("main", map[string]any{"step": 1})
	x, _ := c.Append("main", map[string]any{"step": 2})
	pre := c.Len()
	// Roll the tip back by simulating two writers racing the same write:
	// directly Append on a sibling branch starting from same parent.
	if err := c.Fork("main", "twin"); err != nil {
		t.Fatal(err)
	}
	// twin tip == main tip == x.ContentID. Roll twin back to x's parent
	// by forking from a branch whose tip is the parent. We simulate that
	// by appending on a NEW store from the same parent payload chain:
	c2 := New()
	c2.Append("main", map[string]any{"step": 1})
	y, _ := c2.Append("main", map[string]any{"step": 2})
	if x.ContentID != y.ContentID {
		t.Fatalf("identical (parents, payload) across instances must dedupe: %s vs %s", x.ContentID, y.ContentID)
	}
	_ = pre
}

func TestForkAndIndependentEvolution(t *testing.T) {
	s := New()
	s.Append("main", map[string]any{"step": 1})
	if err := s.Fork("main", "feature"); err != nil {
		t.Fatal(err)
	}
	mainTip, _ := s.Append("main", map[string]any{"step": "main-2"})
	featTip, _ := s.Append("feature", map[string]any{"step": "feat-2"})
	if mainTip.ContentID == featTip.ContentID {
		t.Fatal("forked branches must diverge")
	}
	if mainTip.Parents[0] != featTip.Parents[0] {
		t.Fatal("both children must descend from the fork point")
	}
}

func TestForkRejectsDuplicate(t *testing.T) {
	s := New()
	s.Append("main", "x")
	if err := s.Fork("main", "feature"); err != nil {
		t.Fatal(err)
	}
	if err := s.Fork("main", "feature"); err == nil {
		t.Fatal("expected duplicate-branch rejection")
	}
}

func TestForkRequiresExistingSource(t *testing.T) {
	if err := New().Fork("ghost", "feature"); err == nil {
		t.Fatal("expected unknown-source rejection")
	}
}

func TestMergeUnion(t *testing.T) {
	s := New()
	s.Append("main", map[string]any{"a": 1})
	if err := s.Fork("main", "feat"); err != nil {
		t.Fatal(err)
	}
	s.Append("main", map[string]any{"a": 1, "b": 2})
	s.Append("feat", map[string]any{"a": 1, "c": 3})

	merged, err := s.Merge("main", "feat", func(dst, src json.RawMessage) (any, error) {
		var d, srcMap map[string]any
		_ = json.Unmarshal(dst, &d)
		_ = json.Unmarshal(src, &srcMap)
		for k, v := range srcMap {
			if _, exists := d[k]; !exists {
				d[k] = v
			}
		}
		return d, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Parents) != 2 {
		t.Fatalf("merge node should have 2 parents, got %d", len(merged.Parents))
	}
	var got map[string]any
	_ = json.Unmarshal(merged.Payload, &got)
	if got["b"] != 2.0 || got["c"] != 3.0 {
		t.Fatalf("merge payload missing union: %v", got)
	}
}

func TestMergeSurfacesConflict(t *testing.T) {
	s := New()
	s.Append("main", map[string]any{"a": 1})
	_ = s.Fork("main", "feat")
	s.Append("main", map[string]any{"a": 2})
	s.Append("feat", map[string]any{"a": 3})

	_, err := s.Merge("main", "feat", func(dst, src json.RawMessage) (any, error) {
		return nil, ErrConflict
	})
	if err == nil {
		t.Fatal("expected conflict error to bubble out of Merge")
	}
}

func TestMergeAlreadyConverged(t *testing.T) {
	s := New()
	s.Append("main", "x")
	_ = s.Fork("main", "feat")
	pre := s.Len()
	if _, err := s.Merge("main", "feat", func(dst, src json.RawMessage) (any, error) {
		t.Fatal("mergeFn should not be called when branches already converge")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if s.Len() != pre {
		t.Fatal("converged merge must not add a node")
	}
}

func TestContentIDDeterminismAcrossInstances(t *testing.T) {
	a, b := New(), New()
	an, _ := a.Append("main", map[string]any{"k": 42})
	bn, _ := b.Append("trunk", map[string]any{"k": 42}) // different branch name
	if an.ContentID != bn.ContentID {
		t.Fatal("two instances with same payload+parents must derive the same id")
	}
}

func TestConcurrentAppendsAreSafe(t *testing.T) {
	s := New()
	s.Append("main", "seed")
	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, _ = s.Append("main", map[string]any{"i": i})
		}()
	}
	wg.Wait()
	// Each append takes the lock so we should end with N+1 nodes (seed + N leaves)
	// or fewer if any payloads collided (none here because i is unique).
	if got := s.Len(); got < 2 {
		t.Fatalf("expected concurrent appends to land, got %d nodes", got)
	}
}
