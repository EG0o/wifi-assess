package detection

import (
	"testing"
	"wifi-assess/pkg/models"
)

func TestDuplicateSSIDIsReviewSignal(t *testing.T) {
	aps := []*models.AccessPoint{{BSSID: "a", SSID: "lab"}, {BSSID: "b", SSID: "lab"}, {BSSID: "c", SSID: "other"}, {BSSID: "d"}}
	got := FindDuplicateSSIDs(aps)
	if len(got) != 1 || got[0].SSID != "lab" || len(got[0].BSSIDs) != 2 {
		t.Fatalf("duplicates %+v", got)
	}
	if f := DuplicateSSIDToFinding(got[0]); f.Severity != "Info" || f.RuleID != "duplicate-ssid" {
		t.Fatalf("finding %+v", f)
	}
	aps = append(aps, &models.AccessPoint{BSSID: "e", SSID: "lab"})
	if f := DuplicateSSIDToFinding(FindDuplicateSSIDs(aps)[0]); f.Severity != "Info" {
		t.Fatalf("more BSSIDs unexpectedly escalated: %+v", f)
	}
}
