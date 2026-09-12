package assessment

import (
	"time"

	"wifi-assess/pkg/models"
)

// Engine runs a set of Rules against tracked state and collects findings.
type Engine struct {
	rules []Rule
}

// NewEngine builds an engine with the given rules. Rule order doesn't
// affect which findings are produced — each rule evaluates
// independently — only the order findings come back in for a given AP.
func NewEngine(rules ...Rule) *Engine {
	return &Engine{rules: rules}
}

// DefaultEngine returns an engine wired up with wifi-assess's built-in
// rule set. Extend this (or build a custom Engine via NewEngine) as new
// rules get added.
func DefaultEngine() *Engine {
	return NewEngine(
		OpenNetworkRule{},
		UnknownEncryptionRule{},
		WeakSignalRule{ThresholdDBM: -80},
	)
}

// AssessAccessPoints runs every rule against every AP and returns the
// combined findings, all stamped with the same DetectedAt time — one
// assessment run should read as one point in time, not a spread of
// microsecond-apart timestamps from each individual rule call.
func (e *Engine) AssessAccessPoints(aps []*models.AccessPoint) []models.Finding {
	now := time.Now()

	var findings []models.Finding
	for _, ap := range aps {
		for _, rule := range e.rules {
			for _, f := range rule.Evaluate(ap) {
				f.DetectedAt = now
				findings = append(findings, f)
			}
		}
	}
	return findings
}
