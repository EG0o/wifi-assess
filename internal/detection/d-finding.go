package detection

import (
	"strings"
	"time"

	"wifi-assess/pkg/models"
)

// AnomalyToFinding converts a single anomaly detection into the shared
// Finding shape used across wifi-assess, so anomaly output can be
// reported alongside Phase 4's rule-based findings instead of needing a
// separate report section.
func AnomalyToFinding(f AnomalyFinding) models.Finding {
	return models.Finding{
		BSSID:          f.BSSID,
		RuleID:         "anomaly-" + f.Kind,
		Severity:       confidenceSeverity(ScoreAnomaly(f)),
		Title:          "Baseline anomaly: " + f.Kind,
		Evidence:       f.Detail,
		Recommendation: "Confirm this change is expected (planned AP move, config update, etc.)",
		DetectedAt:     time.Now(),
	}
}

// DuplicateSSIDToFinding converts a duplicate-SSID detection into the
// shared Finding shape.
func DuplicateSSIDToFinding(f DuplicateSSIDFinding) models.Finding {
	return models.Finding{
		SSID:           f.SSID,
		RuleID:         "duplicate-ssid",
		Severity:       confidenceSeverity(ScoreDuplicateSSID(f)),
		Title:          "SSID broadcast by multiple BSSIDs",
		Evidence:       strings.Join(f.BSSIDs, ", "),
		Recommendation: "Confirm every listed BSSID is an AP you control/expect — legitimate multi-AP deployments do this intentionally, so this alone isn't proof of a rogue AP",
		DetectedAt:     time.Now(),
	}
}

// confidenceSeverity maps a Confidence to the same label strings
// assessment.Severity produces. detection intentionally doesn't import
// internal/assessment for this — the two check families are independent
// concerns that happen to report through the same Finding shape — but
// keeping the label spelling identical is what lets a report sort/filter
// findings from both sources consistently.
func confidenceSeverity(c Confidence) string {
	switch c {
	case ConfidenceHigh:
		return "High"
	case ConfidenceSuspicious:
		return "Medium"
	default:
		return "Info"
	}
}
