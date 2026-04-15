package badge

import (
	"strings"
	"testing"
)

func TestSVGConformant(t *testing.T) {
	svg := SVG("ojs-backend-redis", 4, true)
	if !strings.Contains(svg, "<svg") {
		t.Error("SVG should contain <svg tag")
	}
	if !strings.Contains(svg, "L4 Advanced") {
		t.Error("SVG should contain level label")
	}
	if !strings.Contains(svg, "#007ec6") {
		t.Error("SVG should contain blue color for L4")
	}
	if !strings.Contains(svg, "OJS") {
		t.Error("SVG should contain 'OJS' label")
	}
}

func TestSVGNonConformant(t *testing.T) {
	svg := SVG("failing-backend", -1, false)
	if !strings.Contains(svg, "non-conformant") {
		t.Error("SVG should show 'non-conformant' for failing backends")
	}
	if !strings.Contains(svg, "#e05d44") {
		t.Error("SVG should use red color for non-conformant")
	}
}

func TestColorPerLevel(t *testing.T) {
	tests := []struct {
		level      int
		conformant bool
		wantColor  string
	}{
		{0, true, "#dfb317"},
		{1, true, "#a4a61d"},
		{2, true, "#97ca00"},
		{3, true, "#44cc11"},
		{4, true, "#007ec6"},
		{0, false, "#e05d44"},
		{99, true, "#9f9f9f"},
	}
	for _, tt := range tests {
		got := Color(tt.level, tt.conformant)
		if got != tt.wantColor {
			t.Errorf("Color(%d, %v) = %s, want %s", tt.level, tt.conformant, got, tt.wantColor)
		}
	}
}

func TestLevelLabel(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{0, "L0 Core"},
		{1, "L1 Reliable"},
		{2, "L2 Scheduled"},
		{3, "L3 Orchestration"},
		{4, "L4 Advanced"},
		{99, "unknown"},
	}
	for _, tt := range tests {
		got := LevelLabel(tt.level)
		if got != tt.want {
			t.Errorf("LevelLabel(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestXMLEscape(t *testing.T) {
	svg := SVG("test<>&\"", 0, true)
	if strings.Contains(svg, "<test") {
		t.Error("SVG should escape special characters")
	}
}
