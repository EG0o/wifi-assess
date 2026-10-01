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
		Severity:       "Info",
		Title:          "Baseline observation: " + f.Kind,
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
		Severity:       "Info",
		Title:          "SSID broadcast by multiple BSSIDs",
		Evidence:       strings.Join(f.BSSIDs, ", "),
		Recommendation: "Confirm every listed BSSID is an AP you control/expect — legitimate multi-AP deployments do this intentionally, so this alone isn't proof of a rogue AP",
		DetectedAt:     time.Now(),
	}
}
