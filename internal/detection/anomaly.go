package detection

import (
	"fmt"
	"strings"
	"wifi-assess/internal/discovery"
)

// AnomalyFinding describes one deviation between two baselines worth
// surfacing to a human — a newly observed AP, one not observed in the
// current capture, or an existing AP with a changed known field.
type AnomalyFinding struct {
	Kind   string // "new", "missing", "changed"
	BSSID  string
	Detail string
}

// FromBaselineDiff converts a raw BaselineDiff into human-readable
// anomaly findings. They describe observations rather than assigning
// attack confidence; this capture may cover only part of the environment.
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
			Detail: "Access point present in the baseline but not observed in this capture; channel coverage and capture duration may differ",
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
	var details []string
	if c.Before.SSID != "" && c.After.SSID != "" && c.Before.SSID != c.After.SSID {
		details = append(details, fmt.Sprintf("SSID changed from %q to %q", c.Before.SSID, c.After.SSID))
	}
	if c.Before.Channel > 0 && c.After.Channel > 0 && c.Before.Channel != c.After.Channel {
		details = append(details, fmt.Sprintf("Channel changed from %d to %d", c.Before.Channel, c.After.Channel))
	}
	if c.Before.ChannelFrequency > 0 && c.After.ChannelFrequency > 0 && c.Before.ChannelFrequency != c.After.ChannelFrequency {
		details = append(details, fmt.Sprintf("Frequency changed from %d to %d MHz", c.Before.ChannelFrequency, c.After.ChannelFrequency))
	}
	if c.Before.HasCapabilityInfo && c.After.HasCapabilityInfo && c.Before.PrivacyEnabled != c.After.PrivacyEnabled {
		if c.After.PrivacyEnabled {
			details = append(details, "Privacy bit switched from unset to set")
		} else {
			details = append(details, "Privacy bit switched from set to unset")
		}
	}
	return strings.Join(details, "; ")
}
