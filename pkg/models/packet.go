package models

import "time"

// Packet is wifi-assess's normalized representation of a single captured
// 802.11 frame. internal/wifi is responsible for producing these from raw
// gopacket.Packet values, so the rest of the codebase (discovery,
// assessment, reporting) never has to touch gopacket directly.
type Packet struct {
	Timestamp time.Time
	Length    int

	FrameType     string // human-readable, from wifi.FrameType.String()
	FrameCategory string // "Management" / "Control" / "Data" / "Unknown"

	// 802.11 addressing. Not all fields apply to all frame types/directions;
	// zero-value ("") means not present/not applicable for this frame.
	Address1 string // receiver
	Address2 string // transmitter (often the BSSID for AP-originated frames)
	Address3 string // BSSID or destination, depending on frame direction
	Address4 string // only present in WDS frames

	// SSID is populated for beacon/probe frames that carry the SSID
	// information element. Empty covers both "this frame type doesn't
	// carry an SSID" and "hidden/broadcast SSID" — those aren't
	// distinguished at this layer.
	SSID string

	// Channel is read from the DS Parameter Set information element,
	// present on most 2.4GHz beacon/probe-response frames. 0 means the
	// IE wasn't present (e.g. many 5GHz/6GHz networks omit it) — not
	// "channel 0".
	Channel int

	// HasCapabilityInfo/PrivacyEnabled come from the beacon/probe-response
	// capability info field. HasCapabilityInfo gates whether PrivacyEnabled
	// reflects a real observation — false on frame types that don't carry
	// a capability info field at all.
	HasCapabilityInfo bool
	PrivacyEnabled    bool

	// Association response status is meaningful only when HasAssociationStatus
	// is true. Status 0 means success; a request alone cannot establish this.
	HasAssociationStatus  bool
	AssociationStatusCode uint16

	// Radio metadata, only populated when the capture includes a RadioTap
	// header — not guaranteed, it depends on the capturing hardware/driver.
	// Check HasSignal before trusting SignalStrengthDBM.
	HasSignal         bool
	SignalStrengthDBM int
	ChannelFrequency  int
}
