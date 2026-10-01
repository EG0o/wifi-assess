package models

import "time"

// Client is the tracked state for a single wireless station (device),
// built from probe requests and association traffic it sends/receives.
type Client struct {
	MAC string

	// ProbedSSIDs is the set of SSIDs this client has actively probed for.
	// A client probing for many distinct SSIDs — especially ones it isn't
	// currently near — is a common device-fingerprinting/history-leak
	// signal, and feeds Phase 4/5 detection later.
	ProbedSSIDs []string

	// LastAssociationTarget is the AP seen in a request or response; this
	// observation does not establish that association succeeded.
	LastAssociationTarget string

	// AssociatedBSSID is set only after an observed success response. It is
	// evidence of a successful exchange at capture time, not current state.
	AssociatedBSSID string

	FirstSeen time.Time
	LastSeen  time.Time

	ProbeRequestCount int
}
