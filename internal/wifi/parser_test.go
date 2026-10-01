package wifi

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"testing"
)

func dot11Packet(subtype byte, body []byte) gopacket.Packet {
	header := []byte{subtype, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 0}
	frame := append(append(header, body...), 0, 0, 0, 0) // gopacket expects a 4-byte FCS
	return gopacket.NewPacket(frame, layers.LayerTypeDot11, gopacket.Default)
}
func TestManagementInformationElements(t *testing.T) {
	fixed := make([]byte, 12)
	fixed[10] = 0x10
	cases := []struct {
		name            string
		subtype         byte
		body            []byte
		ssid            string
		channel         int
		hasCap, privacy bool
	}{
		{"beacon", 0x80, append(append([]byte{}, fixed...), 0, 3, 'l', 'a', 'b', 3, 1, 11), "lab", 11, true, true},
		{"probe request", 0x40, []byte{0, 3, 'l', 'a', 'b'}, "lab", 0, false, false},
		{"hidden ssid", 0x80, append(append([]byte{}, fixed...), 0, 0, 3, 1, 6), "", 6, true, true},
		{"truncated IE", 0x80, append(append([]byte{}, fixed...), 0, 8, 'x'), "", 0, true, true},
		{"5GHz without DS IE", 0x80, append(append([]byte{}, fixed...), 0, 3, '5', 'G', 'H'), "5GH", 0, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParsePacket(dot11Packet(tc.subtype, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if p.SSID != tc.ssid || p.Channel != tc.channel || p.HasCapabilityInfo != tc.hasCap || p.PrivacyEnabled != tc.privacy {
				t.Fatalf("unexpected parse: %+v", p)
			}
		})
	}
}
func TestAssociationResponseStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   []byte
		has    bool
		status uint16
	}{
		{"success", []byte{0, 0, 0, 0, 1, 0}, true, 0},
		{"failure", []byte{0, 0, 17, 0, 0, 0}, true, 17},
		{"truncated", []byte{0, 0, 0}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParsePacket(dot11Packet(0x10, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if p.HasAssociationStatus != tc.has || p.AssociationStatusCode != tc.status {
				t.Fatalf("status: %+v", p)
			}
		})
	}
}
func TestRadioTapFrequency(t *testing.T) {
	frame := dot11Packet(0x80, make([]byte, 12)).Data()
	radio := []byte{0, 0, 12, 0, 8, 0, 0, 0, 0x3c, 0x14, 0, 0} // channel present; 5180 MHz
	p := gopacket.NewPacket(append(radio, frame...), layers.LayerTypeRadioTap, gopacket.Default)
	parsed, err := ParsePacket(p)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ChannelFrequency != 5180 {
		t.Fatalf("frequency %d", parsed.ChannelFrequency)
	}
}
func TestNonDot11(t *testing.T) {
	p := gopacket.NewPacket([]byte{0, 1, 2, 3}, layers.LayerTypeEthernet, gopacket.Default)
	if _, err := ParsePacket(p); err != ErrNoDot11Layer {
		t.Fatalf("expected ErrNoDot11Layer, got %v", err)
	}
}
