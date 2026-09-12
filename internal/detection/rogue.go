package detection

import "wifi-assess/pkg/models"

// DuplicateSSIDFinding flags an SSID advertised by more than one distinct
// BSSID. This is NOT proof of a rogue AP or evil twin — legitimate
// multi-AP deployments (enterprise WiFi, mesh networks, eduroam-style
// setups) intentionally share one SSID across many BSSIDs. It's a review
// signal: worth a human checking whether every listed BSSID is an AP they
// expect, especially alongside other signals this project doesn't compute
// yet (vendor OUI mismatch, unexpected channel, anomalous signal strength).
type DuplicateSSIDFinding struct {
	SSID   string
	BSSIDs []string
}

// FindDuplicateSSIDs groups tracked APs by SSID and returns every SSID
// seen from more than one distinct BSSID.
func FindDuplicateSSIDs(aps []*models.AccessPoint) []DuplicateSSIDFinding {
	bySSID := make(map[string][]string)
	for _, ap := range aps {
		if ap.SSID == "" {
			continue // hidden/unknown SSIDs can't be meaningfully grouped
		}
		bySSID[ap.SSID] = append(bySSID[ap.SSID], ap.BSSID)
	}

	var out []DuplicateSSIDFinding
	for ssid, bssids := range bySSID {
		if len(bssids) > 1 {
			out = append(out, DuplicateSSIDFinding{SSID: ssid, BSSIDs: bssids})
		}
	}
	return out
}
