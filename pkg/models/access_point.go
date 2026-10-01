package models

import "time"

// AccessPoint is the tracked state for a single wireless access point,
// accumulated across repeated beacon/probe-response observations rather
// than read from a single frame.
type AccessPoint struct {
	BSSID string
	SSID  string // last non-empty SSID seen; empty if never observed (hidden network with no leaking probe response yet)

	Channel          int // from the DS Parameter Set IE; 0 if never observed
	ChannelFrequency int // from RadioTap, in MHz; 0 if never observed

	// HasCapabilityInfo gates whether PrivacyEnabled reflects a real
	// observation (it's only ever set from a beacon or probe response).
	HasCapabilityInfo bool
	PrivacyEnabled    bool

	FirstSeen time.Time
	LastSeen  time.Time

	BeaconCount        int
	ProbeResponseCount int

	// HasSignal gates whether LastSignalStrengthDBM is meaningful — signal
	// data depends on the capturing hardware/driver providing a RadioTap
	// header, which isn't guaranteed.
	HasSignal             bool
	LastSignalStrengthDBM int
	SignalSampleCount     int
	SignalSumDBM          int `json:"-"`
}
