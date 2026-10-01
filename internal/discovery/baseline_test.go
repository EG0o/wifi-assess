package discovery

import "testing"

func TestBaselineDiff(t *testing.T) {
	prev := &Baseline{APs: []BaselineAP{{BSSID: "a", SSID: "lab", Channel: 1, PrivacyEnabled: true}, {BSSID: "b", SSID: "old", Channel: 6, PrivacyEnabled: false}}}
	now := &Baseline{APs: []BaselineAP{{BSSID: "a", SSID: "lab", Channel: 11, PrivacyEnabled: true}, {BSSID: "c", SSID: "new", Channel: 1, PrivacyEnabled: false}}}
	d := prev.Diff(now)
	if len(d.New) != 1 || d.New[0].BSSID != "c" || len(d.Missing) != 1 || d.Missing[0].BSSID != "b" || len(d.Changed) != 1 || d.Changed[0].After.Channel != 11 {
		t.Fatalf("diff %+v", d)
	}
}

func TestBaselineUnknownValuesAndFrequency(t *testing.T) {
	before := &Baseline{APs: []BaselineAP{{BSSID: "ap", SSID: "lab", ChannelFrequency: 5180, HasCapabilityInfo: true, PrivacyEnabled: true}}}
	unknown := &Baseline{APs: []BaselineAP{{BSSID: "ap", SSID: "", ChannelFrequency: 0, HasCapabilityInfo: false}}}
	if diff := before.Diff(unknown); len(diff.Changed) != 0 {
		t.Fatalf("unknown fields should not imply changes: %+v", diff)
	}
	moved := &Baseline{APs: []BaselineAP{{BSSID: "ap", SSID: "lab", ChannelFrequency: 5200, HasCapabilityInfo: true, PrivacyEnabled: true}}}
	if diff := before.Diff(moved); len(diff.Changed) != 1 {
		t.Fatalf("frequency change not reported: %+v", diff)
	}
}
