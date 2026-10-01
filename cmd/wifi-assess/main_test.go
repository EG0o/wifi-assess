package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"wifi-assess/internal/reporting"
)

func fixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "synthetic.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeIEEE802_11); err != nil {
		f.Close()
		t.Fatal(err)
	}
	// Locally administered addresses and invented SSID; no recorded traffic.
	ap := []byte{0x02, 0, 0, 0, 0, 1}
	client := []byte{0x02, 0, 0, 0, 0, 2}
	broadcast := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame := func(subtype byte, dest, src, bssid, body []byte) []byte {
		header := make([]byte, 24)
		header[0] = subtype
		copy(header[4:10], dest)
		copy(header[10:16], src)
		copy(header[16:22], bssid)
		return append(append(header, body...), 0, 0, 0, 0) // dummy FCS
	}
	beacon := make([]byte, 12)
	beacon[10] = 0x10 // privacy bit
	packets := [][]byte{
		frame(0x80, broadcast, ap, ap, append(beacon, 0, 3, 'l', 'a', 'b', 3, 1, 11)),
		frame(0x40, broadcast, client, broadcast, []byte{0, 3, 'l', 'a', 'b'}),
		frame(0x00, ap, client, ap, []byte{0, 0, 0, 0}),
		frame(0x10, client, ap, ap, []byte{0, 0, 0, 0, 1, 0}),
	}
	for i, pkt := range packets {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(i+1), 0), CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestRunCaptureAndBaseline(t *testing.T) {
	path := fixture(t)
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	var out, stderr bytes.Buffer
	if err := run([]string{"-format", "json", "-save-baseline", baseline, path}, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	var r reporting.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.PacketCount != 4 || r.Skipped != 0 {
		t.Fatalf("unexpected counts: %d %d", r.PacketCount, r.Skipped)
	}
	if len(r.AccessPoints) != 1 || r.AccessPoints[0].SSID != "lab" || r.AccessPoints[0].Channel != 11 || !r.AccessPoints[0].PrivacyEnabled {
		t.Fatalf("APs: %+v", r.AccessPoints)
	}
	if len(r.Clients) != 1 || r.Clients[0].ProbeRequestCount != 1 || r.Clients[0].AssociatedBSSID != r.AccessPoints[0].BSSID {
		t.Fatalf("clients: %+v", r.Clients)
	}
	out.Reset()
	if err := run([]string{"-format", "json", "-baseline", baseline, path}, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if strings.HasPrefix(f.RuleID, "anomaly-") {
			t.Fatalf("identical baseline emitted anomaly: %+v", f)
		}
	}
}
func TestInvalidInputs(t *testing.T) {
	// Former live-capture flags must remain unsupported in offline v0.1.
	for _, args := range [][]string{{}, {"-format", "yaml", "capture.pcap"}, {"-interface", "wlan0", "capture.pcap"}, {"-interface", "wlan0", "-duration", "0s"}, {"-baseline", "missing.json", fixture(t)}} {
		var out, stderr bytes.Buffer
		if err := run(args, &out, &stderr); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
