// Package witness tracks witness reputation and enforces diversity
// policies for the Conformance Trust Network (M5/P2).
//
// Witnesses are independent parties that cosign conformance attestations
// to strengthen trust. The reputation system incentivises reliability:
//
//   - Witnesses register with an org identifier and endpoint.
//   - Each cosignature improves the witness's reputation.
//   - Reputation decays if a witness goes offline or fails to respond.
//   - Diversity policy requires cosignatures from distinct organizations.
package witness

import (
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Witness represents a registered witness in the CTN.
type Witness struct {
	ID          string    `json:"id"`
	Org         string    `json:"org"`
	Endpoint    string    `json:"endpoint"`
	KeyID       string    `json:"key_id"`
	RegisteredAt time.Time `json:"registered_at"`
}

// Stats holds the computed reputation stats for a witness.
type Stats struct {
	Witness
	TotalCosigns int       `json:"total_cosigns"`
	SuccessCount int       `json:"success_count"`
	FailureCount int       `json:"failure_count"`
	LastSeen     time.Time `json:"last_seen"`
	Reputation   float64   `json:"reputation"` // 0.0 to 1.0
	Active       bool      `json:"active"`
}

// Registry tracks registered witnesses and their reputation.
type Registry struct {
	mu         sync.RWMutex
	witnesses  map[string]*witnessState
	decayAfter time.Duration
	now        func() time.Time
}

type witnessState struct {
	w            Witness
	totalCosigns int
	successCount int
	failureCount int
	lastSeen     time.Time
}

// maxDecayHalvings caps the reputation decay loop to prevent
// excessive iteration for very stale witnesses. 10 halvings reduce
// reputation to ~0.1% (2^-10 ≈ 0.001).
const maxDecayHalvings = 10

// Config configures the witness registry.
type Config struct {
	// DecayAfter is the duration after which an inactive witness's
	// reputation decays. Default 7 days.
	DecayAfter time.Duration
	// Now is an injectable clock for testing.
	Now func() time.Time
}

// NewRegistry creates a new witness registry.
func NewRegistry(cfg Config) *Registry {
	if cfg.DecayAfter <= 0 {
		cfg.DecayAfter = 7 * 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Registry{
		witnesses:  make(map[string]*witnessState),
		decayAfter: cfg.DecayAfter,
		now:        cfg.Now,
	}
}

// Register adds a witness. Returns error if the ID is already registered
// or required fields are missing.
func (r *Registry) Register(w Witness) error {
	if w.ID == "" {
		return errors.New("witness: id required")
	}
	if w.Org == "" {
		return errors.New("witness: org required")
	}
	if w.Endpoint == "" {
		return errors.New("witness: endpoint required")
	}
	if w.KeyID == "" {
		return errors.New("witness: key_id required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.witnesses[w.ID]; exists {
		return errors.New("witness: already registered: " + w.ID)
	}

	w.RegisteredAt = r.now().UTC()
	r.witnesses[w.ID] = &witnessState{
		w:        w,
		lastSeen: w.RegisteredAt,
	}
	return nil
}

// RecordCosign records that a witness successfully cosigned an entry.
func (r *Registry) RecordCosign(witnessID string, success bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ws, ok := r.witnesses[witnessID]
	if !ok {
		return errors.New("witness: not found: " + witnessID)
	}

	ws.totalCosigns++
	if success {
		ws.successCount++
	} else {
		ws.failureCount++
	}
	ws.lastSeen = r.now().UTC()
	return nil
}

// GetStats returns the reputation stats for a witness.
func (r *Registry) GetStats(witnessID string) (Stats, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ws, ok := r.witnesses[witnessID]
	if !ok {
		return Stats{}, errors.New("witness: not found: " + witnessID)
	}
	return r.computeStats(ws), nil
}

// List returns all witnesses sorted by reputation (descending).
func (r *Registry) List() []Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Stats, 0, len(r.witnesses))
	for _, ws := range r.witnesses {
		result = append(result, r.computeStats(ws))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Reputation > result[j].Reputation
	})
	return result
}

func (r *Registry) computeStats(ws *witnessState) Stats {
	now := r.now().UTC()
	active := now.Sub(ws.lastSeen) < r.decayAfter

	rep := 0.5 // starting reputation
	if ws.totalCosigns > 0 {
		successRate := float64(ws.successCount) / float64(ws.totalCosigns)
		// Weighted: success rate matters most, volume provides bonus
		volumeBonus := float64(ws.totalCosigns) / (float64(ws.totalCosigns) + 20.0)
		rep = successRate*0.7 + volumeBonus*0.3
	}
	if !active {
		elapsed := now.Sub(ws.lastSeen)
		decayPeriods := float64(elapsed) / float64(r.decayAfter)
		// Halve reputation per decay period, capped at 10 halvings
		// (2^-10 ≈ 0.001 — effectively zero reputation). The cap
		// prevents excessive looping for very stale witnesses.
		for i := 0; i < int(decayPeriods) && i < maxDecayHalvings; i++ {
			rep *= 0.5
		}
	}
	if rep > 1.0 {
		rep = 1.0
	}
	if rep < 0.0 {
		rep = 0.0
	}

	return Stats{
		Witness:      ws.w,
		TotalCosigns: ws.totalCosigns,
		SuccessCount: ws.successCount,
		FailureCount: ws.failureCount,
		LastSeen:     ws.lastSeen,
		Reputation:   rep,
		Active:       active,
	}
}

// CheckDiversity verifies that a set of witness IDs come from at least
// minOrgs distinct organizations. Returns nil on success.
func (r *Registry) CheckDiversity(witnessIDs []string, minOrgs int) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	orgs := make(map[string]bool)
	for _, id := range witnessIDs {
		ws, ok := r.witnesses[id]
		if !ok {
			continue
		}
		orgs[ws.w.Org] = true
	}
	if len(orgs) < minOrgs {
		return &DiversityError{
			Required: minOrgs,
			Got:      len(orgs),
			Orgs:     sortedKeys(orgs),
		}
	}
	return nil
}

// DiversityError is returned when witness cosignatures don't meet the
// required organizational diversity.
type DiversityError struct {
	Required int
	Got      int
	Orgs     []string
}

func (e *DiversityError) Error() string {
	return "witness diversity: need " + strconv.Itoa(e.Required) +
		" distinct orgs, got " + strconv.Itoa(e.Got)
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
