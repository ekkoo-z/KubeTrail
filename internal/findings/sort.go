package findings

import (
	"sort"
	"strings"
)

func SortBySeverity(results []Finding) {
	sort.SliceStable(results, func(i, j int) bool {
		return severityRank(results[i].Severity) > severityRank(results[j].Severity)
	})
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 6
	case "high":
		return 5
	case "medium":
		return 4
	case "low":
		return 3
	case "info":
		return 2
	case "unknown":
		return 1
	case "blocked":
		return 0
	default:
		return -1
	}
}
