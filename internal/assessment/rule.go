package assessment

import (
	"fmt"

	"wifi-assess/pkg/models"
)

// Rule evaluates a single tracked access point and returns zero or more
// findings. Rules are intentionally narrow — one concern each — so new
// checks can be added without touching the engine or other rules.
type Rule interface {
	// ID is a short, stable identifier for this rule, used in
	// Finding.RuleID and for enabling/disabling rules later via config.
	ID() string
	// Evaluate inspects a single AP and returns any findings for it. A
	// rule that finds nothing wrong returns nil, not an error.
	Evaluate(ap *models.AccessPoint) []models.Finding
}

// --- Built-in rules ---
//
// Not implemented yet: WPS detection. That needs parsing the WPS vendor
// information element (OUI 00:50:F2, vendor type 4), which internal/wifi
// doesn't extract yet — add it there first, then add a rule here, rather
// than faking a WPS check without the data to back it.

// OpenNetworkRule flags APs observed with the capability info Privacy bit
// unset — no encryption enabled at all.
type OpenNetworkRule struct{}

func (OpenNetworkRule) ID() string { return "open-network" }

func (OpenNetworkRule) Evaluate(ap *models.AccessPoint) []models.Finding {
	if !ap.HasCapabilityInfo || ap.PrivacyEnabled {
		return nil
	}
	return []models.Finding{{
		BSSID:          ap.BSSID,
		SSID:           ap.SSID,
		RuleID:         "open-network",
		Severity:       SeverityHigh.String(),
		Title:          "Open (unencrypted) network",
		Evidence:       "Beacon/probe response capability info has the Privacy bit unset",
		Recommendation: "Enable WPA2/WPA3 unless this network is intentionally open (e.g. a public captive-portal network) with other protections in place",
	}}
}

// UnknownEncryptionRule flags APs we've never actually observed a beacon
// or probe response for, so there's no capability info to judge at all.
// Kept separate from OpenNetworkRule so "confirmed open" and "insufficient
// data" don't get conflated in a report.
type UnknownEncryptionRule struct{}

func (UnknownEncryptionRule) ID() string { return "unknown-encryption" }

func (UnknownEncryptionRule) Evaluate(ap *models.AccessPoint) []models.Finding {
	if ap.HasCapabilityInfo {
		return nil
	}
	return []models.Finding{{
		BSSID:          ap.BSSID,
		SSID:           ap.SSID,
		RuleID:         "unknown-encryption",
		Severity:       SeverityInfo.String(),
		Title:          "Encryption status unknown",
		Evidence:       "No beacon or probe response with capability info was observed for this BSSID",
		Recommendation: "Capture longer, or closer to the AP, to observe a beacon/probe response",
	}}
}

// WeakSignalRule is informational context rather than a security finding —
// flags APs whose last observed signal was weak, which is useful for
// interpreting other findings (a report based on one faint beacon is
// less reliable) but isn't itself a risk.
type WeakSignalRule struct {
	ThresholdDBM int // e.g. -80; anything weaker than this triggers the finding
}

func (WeakSignalRule) ID() string { return "weak-signal" }

func (r WeakSignalRule) Evaluate(ap *models.AccessPoint) []models.Finding {
	if !ap.HasSignal || ap.LastSignalStrengthDBM > r.ThresholdDBM {
		return nil
	}
	return []models.Finding{{
		BSSID:          ap.BSSID,
		SSID:           ap.SSID,
		RuleID:         "weak-signal",
		Severity:       SeverityInfo.String(),
		Title:          "Weak signal at capture time",
		Evidence:       fmt.Sprintf("Last observed signal strength was %d dBm (threshold %d dBm)", ap.LastSignalStrengthDBM, r.ThresholdDBM),
		Recommendation: "No action needed — informational only; other findings for this AP may be based on limited observation",
	}}
}
