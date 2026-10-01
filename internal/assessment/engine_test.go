package assessment

import (
	"testing"
	"wifi-assess/pkg/models"
)

func TestDefaultRules(t *testing.T) {
	aps := []*models.AccessPoint{{BSSID: "open", HasCapabilityInfo: true, PrivacyEnabled: false}, {BSSID: "unknown"}, {BSSID: "weak", HasCapabilityInfo: true, PrivacyEnabled: true, HasSignal: true, LastSignalStrengthDBM: -85, SignalSampleCount: 5, SignalSumDBM: -425}}
	findings := DefaultEngine().AssessAccessPoints(aps)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %+v", findings)
	}
	want := map[string]string{"open": "open-network", "unknown": "unknown-encryption", "weak": "weak-signal"}
	for _, f := range findings {
		if f.RuleID != want[f.BSSID] || f.DetectedAt.IsZero() {
			t.Errorf("unexpected finding %+v", f)
		}
		if f.RuleID == "open-network" && f.Severity != "Medium" {
			t.Errorf("open network severity should be Medium without policy context: %+v", f)
		}
	}
}
