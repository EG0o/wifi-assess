package detection

import "wifi-assess/internal/discovery"

// AnomalyFinding describes one deviation between two baselines worth
// surfacing to a human — a new AP, a disappeared AP, or an existing AP
// whose SSID/channel/privacy setting changed.
type AnomalyFinding struct {
	Kind   string // "new", "missing", "changed"
	BSSID  string
	Detail string
}

// FromBaselineDiff converts a raw BaselineDiff into human-readable
// anomaly findings. This only describes WHAT changed — how alarming each
// change is lives in confidence.go, kept separate so the "what happened"
// description doesn't get tangled up with "how worried should you be".
func FromBaselineDiff(diff discovery.BaselineDiff) []AnomalyFinding {
	var out []AnomalyFinding

	for _, ap := range diff.New {
		out = append(out, AnomalyFinding{
			Kind:   "new",
			BSSID:  ap.BSSID,
			Detail: "New access point not present in the baseline capture",
		})
	}
	for _, ap := range diff.Missing {
		out = append(out, AnomalyFinding{
			Kind:   "missing",
			BSSID:  ap.BSSID,
			Detail: "Access point present in the baseline but not seen in this capture",
		})
	}
	for _, c := range diff.Changed {
		out = append(out, AnomalyFinding{
			Kind:   "changed",
			BSSID:  c.After.BSSID,
			Detail: changeDetail(c),
		})
	}

	return out
}

func changeDetail(c discovery.BaselineAPChange) string {
	switch {
	case c.Before.SSID != c.After.SSID:
		return "SSID changed from \"" + c.Before.SSID + "\" to \"" + c.After.SSID + "\""
	case c.Before.Channel != c.After.Channel:
		return "Channel changed"
	case c.Before.PrivacyEnabled != c.After.PrivacyEnabled:
		if c.After.PrivacyEnabled {
			return "Switched from open to encrypted"
		}
		return "Switched from encrypted to open — worth investigating"
	default:
		return "Changed"
	}
}
