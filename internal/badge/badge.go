// Package badge generates SVG conformance badges for the CTN registry.
package badge

import (
	"strings"
	"text/template"
)

// LevelLabel returns the badge label for a conformance level.
func LevelLabel(level int) string {
	switch level {
	case 0:
		return "L0 Core"
	case 1:
		return "L1 Reliable"
	case 2:
		return "L2 Scheduled"
	case 3:
		return "L3 Orchestration"
	case 4:
		return "L4 Advanced"
	default:
		return "unknown"
	}
}

// Color returns the badge color hex for a conformance level.
func Color(level int, conformant bool) string {
	if !conformant {
		return "#e05d44" // red
	}
	switch level {
	case 0:
		return "#dfb317" // yellow
	case 1:
		return "#a4a61d" // yellow-green
	case 2:
		return "#97ca00" // green
	case 3:
		return "#44cc11" // bright green
	case 4:
		return "#007ec6" // blue (gold tier)
	default:
		return "#9f9f9f" // grey
	}
}

var svgTemplate = template.Must(template.New("badge").Parse(`<svg xmlns="http://www.w3.org/2000/svg" width="{{.TotalWidth}}" height="20" role="img" aria-label="{{.Label}}: {{.Value}}">
  <title>{{.Label}}: {{.Value}}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="{{.TotalWidth}}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{{.LabelWidth}}" height="20" fill="#555"/>
    <rect x="{{.LabelWidth}}" width="{{.ValueWidth}}" height="20" fill="{{.Color}}"/>
    <rect width="{{.TotalWidth}}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="{{.LabelX}}" y="15" fill="#010101" fill-opacity=".3">{{.Label}}</text>
    <text x="{{.LabelX}}" y="14">{{.Label}}</text>
    <text x="{{.ValueX}}" y="15" fill="#010101" fill-opacity=".3">{{.Value}}</text>
    <text x="{{.ValueX}}" y="14">{{.Value}}</text>
  </g>
</svg>`))

// SVG generates a shields.io-style flat SVG badge.
func SVG(backendName string, level int, conformant bool) string {
	label := "OJS"
	var value string
	if !conformant {
		value = "non-conformant"
	} else {
		value = LevelLabel(level)
	}

	labelWidth := len(label)*7 + 10
	valueWidth := len(value)*7 + 10

	data := struct {
		TotalWidth int
		LabelWidth int
		ValueWidth int
		LabelX     int
		ValueX     int
		Label      string
		Value      string
		Color      string
	}{
		TotalWidth: labelWidth + valueWidth,
		LabelWidth: labelWidth,
		ValueWidth: valueWidth,
		LabelX:     labelWidth / 2,
		ValueX:     labelWidth + valueWidth/2,
		Label:      xmlEscape(label),
		Value:      xmlEscape(value),
		Color:      Color(level, conformant),
	}

	var buf strings.Builder
	svgTemplate.Execute(&buf, data)
	return buf.String()
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
