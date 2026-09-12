package detection

// Confidence is a coarse rating of how much attention a detection finding
// deserves — not a statistical probability. This project doesn't have
// enough signal yet (no RF fingerprinting, no vendor OUI database, no
// historical baseline depth) to justify a numeric score. Treat these as
// "how worth a human glance is this", not "how likely is this an attack".
type Confidence int

const (
	ConfidenceReviewOnly Confidence = iota // worth a glance, likely benign
	ConfidenceSuspicious                   // uncommon pattern for legitimate networks
	ConfidenceHigh                         // multiple independent signals line up
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceReviewOnly:
		return "Review"
	case ConfidenceSuspicious:
		return "Suspicious"
	case ConfidenceHigh:
		return "High"
	default:
		return "Unknown"
	}
}

// ScoreAnomaly gives a first-pass confidence rating to a single anomaly
// finding. Deliberately simple — a handful of rules, not a model — meant
// to be refined once real capture data shows which signals actually
// correlate with real incidents versus normal network churn (AP reboots,
// routine config changes, DHCP renewals, etc.).
func ScoreAnomaly(f AnomalyFinding) Confidence {
	switch f.Kind {
	case "changed":
		return ConfidenceSuspicious
	default: // "new", "missing"
		return ConfidenceReviewOnly
	}
}

// ScoreDuplicateSSID gives a first-pass confidence rating to a
// duplicate-SSID finding, based only on how many distinct BSSIDs share
// it. Confidence intentionally goes DOWN as the count grows past a
// couple: an attacker doesn't usually need more than one rogue AP, so a
// large count is far more consistent with a legitimate multi-AP
// deployment than with an active evil-twin attempt.
func ScoreDuplicateSSID(f DuplicateSSIDFinding) Confidence {
	if len(f.BSSIDs) == 2 {
		return ConfidenceSuspicious
	}
	return ConfidenceReviewOnly
}
