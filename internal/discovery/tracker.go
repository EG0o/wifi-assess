package discovery

import (
	"sync"
	"time"

	"wifi-assess/internal/wifi"
	"wifi-assess/pkg/models"
)

// Tracker accumulates per-frame observations (models.Packet) into
// longer-lived AccessPoint and Client state. It's the boundary between
// "one frame at a time" (internal/wifi) and "what does the network look
// like so far" (assessment, detection, reporting).
//
// Zero value is not usable — construct with NewTracker.
type Tracker struct {
	mu      sync.Mutex
	aps     map[string]*models.AccessPoint // keyed by BSSID
	clients map[string]*models.Client      // keyed by MAC
}

func NewTracker() *Tracker {
	return &Tracker{
		aps:     make(map[string]*models.AccessPoint),
		clients: make(map[string]*models.Client),
	}
}

// Observe updates AP/client state from a single parsed frame. Safe for
// concurrent use, though the current file-based CLI processes frames sequentially.
func (t *Tracker) Observe(p *models.Packet) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch p.FrameType {
	case wifi.FrameTypeBeacon.String():
		t.observeAP(p, true)
	case wifi.FrameTypeProbeResponse.String():
		t.observeAP(p, false)
	case wifi.FrameTypeProbeRequest.String():
		t.observeProbeRequest(p)
	case wifi.FrameTypeAssociationRequest.String():
		// A request identifies a target, not a successful association.
		t.observeAssociation(p, p.Address2, p.Address1, false)
	case wifi.FrameTypeAssociationResp.String():
		t.observeAssociation(p, p.Address1, p.Address2, p.HasAssociationStatus && p.AssociationStatusCode == 0)
	}
}

func (t *Tracker) observeAP(p *models.Packet, isBeacon bool) {
	bssid := p.Address2 // transmitter address; for AP-originated mgmt frames this is the BSSID
	if bssid == "" {
		return
	}

	ap, ok := t.aps[bssid]
	if !ok {
		ap = &models.AccessPoint{BSSID: bssid, FirstSeen: p.Timestamp}
		t.aps[bssid] = ap
	}

	if p.SSID != "" {
		ap.SSID = p.SSID
	}
	if p.Channel != 0 {
		ap.Channel = p.Channel
	}
	if p.ChannelFrequency != 0 {
		ap.ChannelFrequency = p.ChannelFrequency
	}
	if p.HasCapabilityInfo {
		ap.HasCapabilityInfo = true
		ap.PrivacyEnabled = p.PrivacyEnabled
	}
	if p.HasSignal {
		ap.HasSignal = true
		ap.LastSignalStrengthDBM = p.SignalStrengthDBM
		ap.SignalSampleCount++
		ap.SignalSumDBM += p.SignalStrengthDBM
	}

	ap.LastSeen = p.Timestamp
	if isBeacon {
		ap.BeaconCount++
	} else {
		ap.ProbeResponseCount++
	}
}

func (t *Tracker) observeProbeRequest(p *models.Packet) {
	mac := p.Address2 // transmitter
	if mac == "" {
		return
	}

	c := t.getOrCreateClient(mac, p.Timestamp)
	c.ProbeRequestCount++
	c.LastSeen = p.Timestamp

	if p.SSID != "" && !containsString(c.ProbedSSIDs, p.SSID) {
		c.ProbedSSIDs = append(c.ProbedSSIDs, p.SSID)
	}
}

func (t *Tracker) observeAssociation(p *models.Packet, clientMAC, apBSSID string, success bool) {
	if clientMAC == "" {
		return
	}

	c := t.getOrCreateClient(clientMAC, p.Timestamp)
	c.LastSeen = p.Timestamp
	if apBSSID != "" {
		c.LastAssociationTarget = apBSSID
		if success {
			c.AssociatedBSSID = apBSSID
		}
	}
}

func (t *Tracker) getOrCreateClient(mac string, firstSeen time.Time) *models.Client {
	c, ok := t.clients[mac]
	if !ok {
		c = &models.Client{MAC: mac, FirstSeen: firstSeen}
		t.clients[mac] = c
	}
	return c
}

// AccessPoints returns a snapshot slice of all tracked APs. The returned
// pointers alias internal state — treat them as read-only.
func (t *Tracker) AccessPoints() []*models.AccessPoint {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]*models.AccessPoint, 0, len(t.aps))
	for _, ap := range t.aps {
		out = append(out, ap)
	}
	return out
}

// Clients returns a snapshot slice of all tracked clients.
func (t *Tracker) Clients() []*models.Client {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]*models.Client, 0, len(t.clients))
	for _, c := range t.clients {
		out = append(out, c)
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
