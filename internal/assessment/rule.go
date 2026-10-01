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

// OpenNetworkRule flags APs that advertise the capability Privacy bit unset.
// This is an observation; whether an open network violates policy depends on
// the deployment. A public guest network may intentionally be open.
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
		Severity:       SeverityMedium.String(),
		Title:          "Network advertises an unset Privacy bit",
		Evidence:       "Beacon/probe response capability info has the Privacy bit unset",
		Recommendation: "Review whether this network is intentionally open; if WLAN confidentiality is required, enable an appropriate WPA2/WPA3 configuration",
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
// flags consistently low observed signal in this capture. Signal depends on
// the receiver position and hardware, and is not a security risk itself.
type WeakSignalRule struct {
	ThresholdDBM int // e.g. -80; anything weaker than this triggers the finding
}

func (WeakSignalRule) ID() string { return "weak-signal" }

func (r WeakSignalRule) Evaluate(ap *models.AccessPoint) []models.Finding {
	if ap.SignalSampleCount < 5 {
		return nil
	}
	average := ap.SignalSumDBM / ap.SignalSampleCount
	if average > r.ThresholdDBM {
		return nil
	}
	return []models.Finding{{
		BSSID:          ap.BSSID,
		SSID:           ap.SSID,
		RuleID:         "weak-signal",
		Severity:       SeverityInfo.String(),
		Title:          "Low average received signal in this capture",
		Evidence:       fmt.Sprintf("Mean of %d signal samples was %d dBm (threshold %d dBm)", ap.SignalSampleCount, average, r.ThresholdDBM),
		Recommendation: "No action needed — informational only; other findings for this AP may be based on limited observation",
	}}
}
