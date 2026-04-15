package witness

import (
	"testing"
	"time"
)

func TestRegisterAndList(t *testing.T) {
	r := NewRegistry(Config{})

	if err := r.Register(Witness{ID: "w1", Org: "acme", Endpoint: "https://w1.example.com", KeyID: "key1"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(Witness{ID: "w2", Org: "bigcorp", Endpoint: "https://w2.example.com", KeyID: "key2"}); err != nil {
		t.Fatal(err)
	}

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("List() = %d, want 2", len(list))
	}
}

func TestRegisterDuplicate(t *testing.T) {
	r := NewRegistry(Config{})
	w := Witness{ID: "w1", Org: "acme", Endpoint: "https://w1.example.com", KeyID: "key1"}
	if err := r.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(w); err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestRegisterValidation(t *testing.T) {
	r := NewRegistry(Config{})

	tests := []struct {
		name string
		w    Witness
	}{
		{"missing id", Witness{Org: "a", Endpoint: "e", KeyID: "k"}},
		{"missing org", Witness{ID: "w", Endpoint: "e", KeyID: "k"}},
		{"missing endpoint", Witness{ID: "w", Org: "a", KeyID: "k"}},
		{"missing key_id", Witness{ID: "w", Org: "a", Endpoint: "e"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := r.Register(tt.w); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestRecordCosignAndReputation(t *testing.T) {
	r := NewRegistry(Config{})
	r.Register(Witness{ID: "w1", Org: "acme", Endpoint: "https://w1.example.com", KeyID: "key1"})

	// Record 10 successes
	for i := 0; i < 10; i++ {
		if err := r.RecordCosign("w1", true); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := r.GetStats("w1")
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalCosigns != 10 {
		t.Errorf("TotalCosigns = %d, want 10", stats.TotalCosigns)
	}
	if stats.SuccessCount != 10 {
		t.Errorf("SuccessCount = %d, want 10", stats.SuccessCount)
	}
	if stats.Reputation <= 0.5 {
		t.Errorf("Reputation = %f, should be > 0.5 after 10 successes", stats.Reputation)
	}
	if !stats.Active {
		t.Error("should be active")
	}
}

func TestRecordCosignFailure(t *testing.T) {
	r := NewRegistry(Config{})
	r.Register(Witness{ID: "w1", Org: "acme", Endpoint: "https://w1.example.com", KeyID: "key1"})

	// All failures
	for i := 0; i < 10; i++ {
		r.RecordCosign("w1", false)
	}

	stats, _ := r.GetStats("w1")
	if stats.FailureCount != 10 {
		t.Errorf("FailureCount = %d, want 10", stats.FailureCount)
	}
	if stats.Reputation > 0.3 {
		t.Errorf("Reputation = %f, should be low after all failures", stats.Reputation)
	}
}

func TestRecordCosignUnknown(t *testing.T) {
	r := NewRegistry(Config{})
	if err := r.RecordCosign("nonexistent", true); err == nil {
		t.Error("expected error for unknown witness")
	}
}

func TestReputationDecay(t *testing.T) {
	now := time.Now()
	clock := now
	r := NewRegistry(Config{
		DecayAfter: 24 * time.Hour,
		Now:        func() time.Time { return clock },
	})

	r.Register(Witness{ID: "w1", Org: "acme", Endpoint: "https://w1.example.com", KeyID: "key1"})
	for i := 0; i < 10; i++ {
		r.RecordCosign("w1", true)
	}

	stats1, _ := r.GetStats("w1")
	rep1 := stats1.Reputation

	// Advance clock past decay period
	clock = now.Add(3 * 24 * time.Hour)

	stats2, _ := r.GetStats("w1")
	if stats2.Active {
		t.Error("should be inactive after decay period")
	}
	if stats2.Reputation >= rep1 {
		t.Errorf("reputation should decay: was %f, now %f", rep1, stats2.Reputation)
	}
}

func TestCheckDiversity(t *testing.T) {
	r := NewRegistry(Config{})
	r.Register(Witness{ID: "w1", Org: "acme", Endpoint: "https://w1.example.com", KeyID: "key1"})
	r.Register(Witness{ID: "w2", Org: "acme", Endpoint: "https://w2.example.com", KeyID: "key2"})
	r.Register(Witness{ID: "w3", Org: "bigcorp", Endpoint: "https://w3.example.com", KeyID: "key3"})
	r.Register(Witness{ID: "w4", Org: "indie", Endpoint: "https://w4.example.com", KeyID: "key4"})

	// Same org → fails diversity
	if err := r.CheckDiversity([]string{"w1", "w2"}, 2); err == nil {
		t.Error("expected diversity error for same-org witnesses")
	}

	// Two different orgs → passes
	if err := r.CheckDiversity([]string{"w1", "w3"}, 2); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Three different orgs required
	if err := r.CheckDiversity([]string{"w1", "w3"}, 3); err == nil {
		t.Error("expected diversity error for 2 orgs when 3 required")
	}

	// Three different orgs provided
	if err := r.CheckDiversity([]string{"w1", "w3", "w4"}, 3); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiversityErrorMessage(t *testing.T) {
	err := &DiversityError{Required: 3, Got: 1, Orgs: []string{"acme"}}
	msg := err.Error()
	if msg != "witness diversity: need 3 distinct orgs, got 1" {
		t.Errorf("unexpected error message: %s", msg)
	}
}
