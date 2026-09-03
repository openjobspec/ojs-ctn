package store

import "encoding/json"

type reportProjection struct {
	backend *struct {
		Name string `json:"name"`
	}
	target          string
	runAt           string
	conformantLevel int
	conformant      bool
	documentErr     error
	backendErr      error
	targetErr       error
	runAtErr        error
	levelErr        error
	conformantErr   error
}

func decodeReportProjection(report json.RawMessage) reportProjection {
	var raw struct {
		Backend         json.RawMessage `json:"backend"`
		Target          json.RawMessage `json:"target"`
		RunAt           json.RawMessage `json:"run_at"`
		ConformantLevel json.RawMessage `json:"conformant_level"`
		Conformant      json.RawMessage `json:"conformant"`
	}
	if err := json.Unmarshal(report, &raw); err != nil {
		return reportProjection{documentErr: err}
	}

	var projection reportProjection
	if len(raw.Backend) > 0 {
		projection.backendErr = json.Unmarshal(raw.Backend, &projection.backend)
	}
	if len(raw.Target) > 0 {
		projection.targetErr = json.Unmarshal(raw.Target, &projection.target)
	}
	if len(raw.RunAt) > 0 {
		projection.runAtErr = json.Unmarshal(raw.RunAt, &projection.runAt)
	}
	if len(raw.ConformantLevel) > 0 {
		projection.levelErr = json.Unmarshal(raw.ConformantLevel, &projection.conformantLevel)
	}
	if len(raw.Conformant) > 0 {
		projection.conformantErr = json.Unmarshal(raw.Conformant, &projection.conformant)
	}
	return projection
}

func (p reportProjection) backendName() string {
	if p.documentErr != nil || p.backendErr != nil || p.targetErr != nil {
		return ""
	}
	if p.backend != nil && p.backend.Name != "" {
		return p.backend.Name
	}
	return p.target
}

func (p reportProjection) runTimestamp() string {
	if p.documentErr != nil || p.runAtErr != nil {
		return ""
	}
	return p.runAt
}

func (p reportProjection) conformanceLevel() int {
	if p.documentErr != nil || p.levelErr != nil {
		return -1
	}
	return p.conformantLevel
}

func (p reportProjection) isConformant() bool {
	if p.documentErr != nil || p.conformantErr != nil {
		return false
	}
	return p.conformant
}

// extractBackendName pulls the backend name from a report JSON blob.
// Checks report.backend.name first, then falls back to report.target.
func extractBackendName(report json.RawMessage) string {
	return decodeReportProjection(report).backendName()
}

func extractRunAt(report json.RawMessage) string {
	return decodeReportProjection(report).runTimestamp()
}

// ExtractConformantLevel pulls the conformant_level from a report JSON blob.
func ExtractConformantLevel(report json.RawMessage) int {
	return extractConformantLevel(report)
}

// ExtractConformant pulls the conformant flag from a report JSON blob.
func ExtractConformant(report json.RawMessage) bool {
	return extractConformant(report)
}

// ExtractBackendName pulls the backend name from a report JSON blob.
func ExtractBackendName(report json.RawMessage) string {
	return extractBackendName(report)
}

// ExtractRunAt pulls the run_at timestamp from a report JSON blob.
func ExtractRunAt(report json.RawMessage) string {
	return extractRunAt(report)
}

func extractConformantLevel(report json.RawMessage) int {
	return decodeReportProjection(report).conformanceLevel()
}

func extractConformant(report json.RawMessage) bool {
	return decodeReportProjection(report).isConformant()
}
