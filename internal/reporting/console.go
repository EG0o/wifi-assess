package reporting

import (
	"fmt"
	"io"
	"sort"
)

func WriteConsole(w io.Writer, r Report) error {
	if _, err := fmt.Fprintf(w, "WiFi-Assess\n===========\nCapture: %s\nPackets: %d\nNon-802.11 / unparsed: %d\n\nFrame types:\n", r.Source, r.PacketCount, r.Skipped); err != nil {
		return err
	}
	keys := make([]string, 0, len(r.FrameCounts))
	for k := range r.FrameCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := fmt.Fprintf(w, "  %-30s %d\n", k, r.FrameCounts[k]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nAccess points (%d):\n", len(r.AccessPoints)); err != nil {
		return err
	}
	for _, ap := range r.AccessPoints {
		privacy := "privacy=?"
		if ap.HasCapabilityInfo {
			if ap.PrivacyEnabled {
				privacy = "privacy=set"
			} else {
				privacy = "privacy=unset"
			}
		}
		ssid := ap.SSID
		if ssid == "" {
			ssid = "<hidden/unknown>"
		}
		if _, err := fmt.Fprintf(w, "  %-17s  ch=%-3d  %-9s  beacons=%-5d probe_resp=%-5d  %s\n", ap.BSSID, ap.Channel, privacy, ap.BeaconCount, ap.ProbeResponseCount, ssid); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nClients (%d):\n", len(r.Clients)); err != nil {
		return err
	}
	for _, c := range r.Clients {
		assoc := c.AssociatedBSSID
		if assoc == "" {
			assoc = "-"
		}
		target := c.LastAssociationTarget
		if target == "" {
			target = "-"
		}
		if _, err := fmt.Fprintf(w, "  %-17s  probes=%-5d  assoc_success=%s  assoc_target=%s  probed_ssids=%v\n", c.MAC, c.ProbeRequestCount, assoc, target, c.ProbedSSIDs); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nFindings (%d):\n", len(r.Findings)); err != nil {
		return err
	}
	for _, f := range r.Findings {
		label := f.BSSID
		if f.SSID != "" {
			if label != "" {
				label += " (" + f.SSID + ")"
			} else {
				label = f.SSID
			}
		}
		if _, err := fmt.Fprintf(w, "  [%-10s] %-30s %s\n               Evidence: %s\n               Recommendation: %s\n", f.Severity, label, f.Title, f.Evidence, f.Recommendation); err != nil {
			return err
		}
	}
	return nil
}
