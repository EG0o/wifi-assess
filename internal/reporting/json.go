package reporting

import (
	"encoding/json"
	"io"
	"time"
	"wifi-assess/pkg/models"
)

type Report struct {
	CapturedAt   time.Time             `json:"captured_at"`
	Source       string                `json:"source"`
	PacketCount  int                   `json:"packets"`
	Skipped      int                   `json:"non_80211_or_unparsed"`
	FrameCounts  map[string]int        `json:"frame_counts"`
	AccessPoints []*models.AccessPoint `json:"access_points"`
	Clients      []*models.Client      `json:"clients"`
	Findings     []models.Finding      `json:"findings"`
}

func WriteJSON(w io.Writer, r Report) error {
	if r.FrameCounts == nil {
		r.FrameCounts = map[string]int{}
	}
	if r.AccessPoints == nil {
		r.AccessPoints = []*models.AccessPoint{}
	}
	if r.Clients == nil {
		r.Clients = []*models.Client{}
	}
	if r.Findings == nil {
		r.Findings = []models.Finding{}
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}
