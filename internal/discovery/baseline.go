package discovery

import (
	"sort"
	"time"
)

// Baseline is a point-in-time snapshot of the AP set a Tracker has seen,
// intended for later comparison as an observation of capture differences.
// Persisted as JSON (see internal/storage) — chosen over SQLite since
// this is one flat snapshot per run, read/written wholesale rather than
// queried; revisit only if querying across many stored runs becomes an
// actual need.
type Baseline struct {
	CapturedAt time.Time    `json:"captured_at"`
	APs        []BaselineAP `json:"access_points"`
}

// BaselineAP is the subset of AccessPoint fields worth comparing across
// captures — identity and radio parameters, not live counters like
// BeaconCount that reset every run and would show up as "changed" even
// when nothing meaningful did.
type BaselineAP struct {
	BSSID             string `json:"bssid"`
	SSID              string `json:"ssid"`
	Channel           int    `json:"channel"`
	ChannelFrequency  int    `json:"channel_frequency"`
	PrivacyEnabled    bool   `json:"privacy_enabled"`
	HasCapabilityInfo bool   `json:"has_capability_info,omitempty"`
}

// NewBaseline snapshots the current state of a Tracker.
func NewBaseline(t *Tracker) *Baseline {
	aps := t.AccessPoints()
	b := &Baseline{
		CapturedAt: time.Now(),
		APs:        make([]BaselineAP, 0, len(aps)),
	}
	for _, ap := range aps {
		b.APs = append(b.APs, BaselineAP{
			BSSID:             ap.BSSID,
			SSID:              ap.SSID,
			Channel:           ap.Channel,
			ChannelFrequency:  ap.ChannelFrequency,
			PrivacyEnabled:    ap.PrivacyEnabled,
			HasCapabilityInfo: ap.HasCapabilityInfo,
		})
	}
	sort.Slice(b.APs, func(i, j int) bool { return b.APs[i].BSSID < b.APs[j].BSSID })
	return b
}

// BaselineDiff is the result of comparing two baselines. This is
// intentionally basic and cannot establish whether any AP is unauthorized.
type BaselineDiff struct {
	New     []BaselineAP
	Missing []BaselineAP
	Changed []BaselineAPChange
}

type BaselineAPChange struct {
	Before BaselineAP
	After  BaselineAP
}

// Diff compares b (the earlier baseline) against other (the later one)
// and reports which APs are new, missing, or changed in a way that
// matters for review: known SSID, channel, frequency or privacy bit changed
// for the same BSSID. A field unknown in either capture is not a change.
func (b *Baseline) Diff(other *Baseline) BaselineDiff {
	before := make(map[string]BaselineAP, len(b.APs))
	for _, ap := range b.APs {
		before[ap.BSSID] = ap
	}
	after := make(map[string]BaselineAP, len(other.APs))
	for _, ap := range other.APs {
		after[ap.BSSID] = ap
	}

	var diff BaselineDiff
	for bssid, a := range after {
		bfr, existed := before[bssid]
		if !existed {
			diff.New = append(diff.New, a)
			continue
		}
		if changedAP(bfr, a) {
			diff.Changed = append(diff.Changed, BaselineAPChange{Before: bfr, After: a})
		}
	}
	for bssid, bfr := range before {
		if _, stillPresent := after[bssid]; !stillPresent {
			diff.Missing = append(diff.Missing, bfr)
		}
	}
	sort.Slice(diff.New, func(i, j int) bool { return diff.New[i].BSSID < diff.New[j].BSSID })
	sort.Slice(diff.Missing, func(i, j int) bool { return diff.Missing[i].BSSID < diff.Missing[j].BSSID })
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].After.BSSID < diff.Changed[j].After.BSSID })
	return diff
}

// Unknown fields in either capture are not treated as evidence of a change.
func changedAP(before, after BaselineAP) bool {
	return before.SSID != "" && after.SSID != "" && before.SSID != after.SSID ||
		before.Channel > 0 && after.Channel > 0 && before.Channel != after.Channel ||
		before.ChannelFrequency > 0 && after.ChannelFrequency > 0 && before.ChannelFrequency != after.ChannelFrequency ||
		before.HasCapabilityInfo && after.HasCapabilityInfo && before.PrivacyEnabled != after.PrivacyEnabled
}
