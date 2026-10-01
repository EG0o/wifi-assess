package wifi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"wifi-assess/pkg/models"
)

// ErrNoDot11Layer is returned by ParsePacket when the given packet does not
// contain an 802.11 MAC layer — e.g. non-wifi traffic that ended up in the
// capture, or a frame gopacket couldn't decode.
var ErrNoDot11Layer = errors.New("wifi: packet does not contain an 802.11 layer")

// ParsePacket extracts the fields wifi-assess cares about from a raw
// gopacket.Packet and returns them as a models.Packet.
func ParsePacket(pkt gopacket.Packet) (*models.Packet, error) {
	dot11Layer := pkt.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, ErrNoDot11Layer
	}

	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil, fmt.Errorf("wifi: unexpected type for Dot11 layer: %T", dot11Layer)
	}

	frameType := FrameType(dot11.Type)

	p := &models.Packet{
		Timestamp:     pkt.Metadata().Timestamp,
		Length:        pkt.Metadata().Length,
		FrameType:     frameType.String(),
		FrameCategory: frameType.Category().String(),
		Address1:      dot11.Address1.String(),
		Address2:      dot11.Address2.String(),
		Address3:      dot11.Address3.String(),
	}

	if !isZeroMAC(dot11.Address4) {
		p.Address4 = dot11.Address4.String()
	}

	if radio := extractRadioTap(pkt); radio != nil {
		p.HasSignal = radio.hasSignal
		p.SignalStrengthDBM = radio.signalDBM
		p.ChannelFrequency = radio.channelFreq
	}

	// gopacket's automatic layer chaining is unreliable across mgmt frame
	// subtypes: probe request frames have no fixed fields and fall back
	// to Dot11Mgmt.DecodeFromBytes, which sets Contents but never Payload —
	// so pkt.Layers() silently yields zero information elements with no
	// error at all. Walking dot11.Payload ourselves works uniformly across
	// beacon, probe request, and probe response frames instead of relying
	// on that chain.
	switch frameType {
	case FrameTypeBeacon, FrameTypeProbeResponse, FrameTypeProbeRequest:
		ssid, channel, capInfo, hasCapInfo := extractIEsAndCapability(frameType, dot11.Payload)
		p.SSID = ssid
		p.Channel = channel
		if hasCapInfo {
			p.HasCapabilityInfo = true
			p.PrivacyEnabled = capInfo&dot11CapabilityPrivacyBit != 0
		}
	case FrameTypeAssociationResp:
		// Capability (2), status (2), association ID (2).
		if len(dot11.Payload) >= 6 {
			p.HasAssociationStatus = true
			p.AssociationStatusCode = binary.LittleEndian.Uint16(dot11.Payload[2:4])
		}
	}

	return p, nil
}

// dot11MgmtFixedFieldsLength is the size, in bytes, of the fixed
// Timestamp(8) + Interval(2) + Capability(2) fields that precede the
// information elements in beacon and probe-response frames. Probe
// requests have no fixed fields at all — their body is IEs from byte 0.
const dot11MgmtFixedFieldsLength = 12

// dot11CapabilityPrivacyBit is bit 4 (0x0010) of the 802.11 capability
// info field, set when the AP requires encryption (WEP/WPA/WPA2/WPA3 —
// the capability field alone can't distinguish which; that needs the
// RSN/WPA information elements, which are not parsed in this release).
const dot11CapabilityPrivacyBit = 0x0010

// extractIEsAndCapability manually walks the raw information-element
// byte stream from a management frame's payload rather than trusting
// gopacket's layer chain (see the comment above ParsePacket's call site
// for why). Returns zero values for whatever wasn't present or the data
// was truncated before reaching.
func extractIEsAndCapability(frameType FrameType, payload []byte) (ssid string, channel int, capInfo uint16, hasCapInfo bool) {
	data := payload

	switch frameType {
	case FrameTypeBeacon, FrameTypeProbeResponse:
		if len(data) < dot11MgmtFixedFieldsLength {
			return "", 0, 0, false
		}
		capInfo = binary.LittleEndian.Uint16(data[10:12])
		hasCapInfo = true
		data = data[dot11MgmtFixedFieldsLength:]
	case FrameTypeProbeRequest:
		// No fixed fields — information elements start immediately.
	default:
		return "", 0, 0, false
	}

	for len(data) >= 2 {
		id := data[0]
		length := int(data[1])
		if len(data) < 2+length {
			break // truncated IE — stop rather than reading out of bounds
		}
		info := data[2 : 2+length]
		switch layers.Dot11InformationElementID(id) {
		case layers.Dot11InformationElementIDSSID:
			ssid = string(info)
		case layers.Dot11InformationElementIDDSSet:
			if len(info) == 1 {
				channel = int(info[0])
			}
		}
		data = data[2+length:]
	}

	return ssid, channel, capInfo, hasCapInfo
}

type radioInfo struct {
	hasSignal   bool
	signalDBM   int
	channelFreq int
}

// extractRadioTap pulls signal/channel metadata out of the RadioTap header,
// if the capture includes one. Not all captures do — it depends entirely on
// the capturing driver/hardware, so callers must treat a nil result as
// "unknown," not "no signal."
func extractRadioTap(pkt gopacket.Packet) *radioInfo {
	radioLayer := pkt.Layer(layers.LayerTypeRadioTap)
	if radioLayer == nil {
		return nil
	}

	radio, ok := radioLayer.(*layers.RadioTap)
	if !ok {
		return nil
	}

	info := &radioInfo{}
	if radio.Present.DBMAntennaSignal() {
		info.hasSignal = true
		info.signalDBM = int(radio.DBMAntennaSignal)
	}
	if radio.Present.Channel() {
		info.channelFreq = int(radio.ChannelFrequency)
	}
	return info
}

func isZeroMAC(addr net.HardwareAddr) bool {
	if len(addr) == 0 {
		return true
	}
	for _, b := range addr {
		if b != 0 {
			return false
		}
	}
	return true
}
