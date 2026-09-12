// Package storage handles persisting discovery baselines between runs.
//
// JSON, not SQLite: baseline data is one flat snapshot per run, read and
// written wholesale rather than queried, so there's no case yet for a
// relational store — and SQLite drivers need either cgo or a large
// pure-Go implementation, both added complexity for no current benefit.
// Revisit if/when querying across many stored historical runs becomes an
// actual need.
package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"wifi-assess/internal/discovery"
)

// SaveBaseline writes a baseline snapshot to disk as indented JSON.
func SaveBaseline(path string, b *discovery.Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: marshaling baseline: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("storage: writing baseline to %s: %w", path, err)
	}
	return nil
}

// LoadBaseline reads a baseline snapshot previously written by SaveBaseline.
func LoadBaseline(path string) (*discovery.Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("storage: reading baseline from %s: %w", path, err)
	}
	var b discovery.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("storage: unmarshaling baseline from %s: %w", path, err)
	}
	return &b, nil
}
