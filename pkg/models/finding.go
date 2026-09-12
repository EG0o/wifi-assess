package models

import "time"

// Finding is a single assessment or detection result. It's the shared
// output shape for both internal/assessment (rule-based checks) and
// internal/detection (anomaly/duplicate-SSID checks), so reporting can
// treat them uniformly instead of needing a separate code path per source.
//
// Severity is a plain string ("Info"/"Low"/"Medium"/"High"/"Critical")
// rather than a shared enum type, deliberately: pkg/models sits below
// internal/assessment and internal/detection in the dependency graph, so
// it can't import either of them without a cycle. Both packages produce
// labels matching assessment.Severity.String() so sorting/filtering by
// severity still works consistently across sources.
type Finding struct {
	BSSID string
	SSID  string

	RuleID         string
	Severity       string
	Title          string
	Evidence       string
	Recommendation string

	DetectedAt time.Time
}
