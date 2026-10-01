package discovery

import (
	"testing"
	"time"
	"wifi-assess/internal/wifi"
	"wifi-assess/pkg/models"
)

func TestAssociationRequiresSuccessResponse(t *testing.T) {
	tr := NewTracker()
	ts := time.Now()
	mac := "00:11:22:33:44:55"
	ap := "66:77:88:99:aa:bb"
	tr.Observe(&models.Packet{Timestamp: ts, FrameType: wifi.FrameTypeAssociationRequest.String(), Address1: ap, Address2: mac})
	c := tr.Clients()[0]
	if c.AssociatedBSSID != "" || c.LastAssociationTarget != ap {
		t.Fatalf("request implied success: %+v", c)
	}
	tr.Observe(&models.Packet{Timestamp: ts, FrameType: wifi.FrameTypeAssociationResp.String(), Address1: mac, Address2: ap, HasAssociationStatus: true, AssociationStatusCode: 17})
	if c.AssociatedBSSID != "" {
		t.Fatalf("failed response implied success: %+v", c)
	}
	tr.Observe(&models.Packet{Timestamp: ts, FrameType: wifi.FrameTypeAssociationResp.String(), Address1: mac, Address2: ap, HasAssociationStatus: true, AssociationStatusCode: 0})
	if c.AssociatedBSSID != ap {
		t.Fatalf("success not recorded: %+v", c)
	}
}
