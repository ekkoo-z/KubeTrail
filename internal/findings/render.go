package findings

import (
	"fmt"
	"io"
	"strings"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[1;31m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[1;36m"
	colorGreen  = "\033[1;32m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func Render(w io.Writer, results []Finding, color bool, outputPath string) {
	if len(results) == 0 {
		line := "No high-risk findings detected."
		if color {
			line = colorGreen + line + colorReset
		}
		fmt.Fprintln(w, line)
		if outputPath != "" && outputPath != "-" {
			fmt.Fprintf(w, "Full results written to: %s\n", outputPath)
		}
		return
	}

	sorted := append([]Finding(nil), results...)
	SortBySeverity(sorted)

	// Confirmed/probable escapes get their own highlight box at the top; the
	// remaining signal-level findings stay in the general attack-surface box.
	var escapeBox, surfaceBox []Finding
	for _, f := range sorted {
		if f.Category == "escape" && (f.Confidence == "confirmed" || f.Confidence == "probable") {
			escapeBox = append(escapeBox, f)
		} else {
			surfaceBox = append(surfaceBox, f)
		}
	}
	if len(escapeBox) > 0 {
		renderSection(w, "Confirmed / Probable Container Escape", escapeBox, color)
		if len(surfaceBox) > 0 {
			fmt.Fprintln(w)
		}
	}
	if len(surfaceBox) > 0 {
		renderSection(w, "Attack Surface Risk Findings", surfaceBox, color)
	}

	fmt.Fprintln(w)
	renderSummary(w, results, color)
	if outputPath != "" && outputPath != "-" {
		fmt.Fprintf(w, "Full results written to: %s\n", outputPath)
	}
}

func renderSection(w io.Writer, title string, results []Finding, color bool) {
	header := fmt.Sprintf("─── %s ", title)
	header += strings.Repeat("─", max(0, 68-len([]rune(header))))
	if color {
		fmt.Fprintf(w, "%s%s%s\n", colorBold, header, colorReset)
	} else {
		fmt.Fprintln(w, header)
	}

	fmt.Fprintf(w, " %-8s │ %-9s │ %-58s │ %s\n", "SEVERITY", "CONF", "FINDING", "EVIDENCE")
	fmt.Fprintf(w, "%s┼%s┼%s┼%s\n",
		strings.Repeat("─", 10),
		strings.Repeat("─", 11),
		strings.Repeat("─", 60),
		strings.Repeat("─", 26))

	for _, f := range results {
		sev := strings.ToUpper(f.Severity)
		if color {
			sev = severityColor(f.Severity) + sev + colorReset
		}
		confidence := f.Confidence
		if confidence == "" {
			confidence = "-"
		}
		title := truncate(f.Title, 58)
		evidence := truncate(f.Evidence, 24)
		fmt.Fprintf(w, " %-8s │ %-9s │ %-58s │ %s\n", sev, confidence, title, evidence)
	}
}

func renderSummary(w io.Writer, results []Finding, color bool) {
	critical, high, medium := 0, 0, 0
	for _, f := range results {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		}
	}

	if color {
		fmt.Fprintf(w, "Summary: %s%d critical%s, %s%d high%s, %s%d medium%s\n",
			colorRed, critical, colorReset,
			colorYellow, high, colorReset,
			colorCyan, medium, colorReset)
	} else {
		fmt.Fprintf(w, "Summary: %d critical, %d high, %d medium\n", critical, high, medium)
	}
}

func severityColor(severity string) string {
	switch severity {
	case "critical":
		return colorRed
	case "high":
		return colorYellow
	case "medium":
		return colorCyan
	default:
		return ""
	}
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-1]) + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
