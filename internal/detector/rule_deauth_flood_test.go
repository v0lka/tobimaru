package detector

import (
	"net"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func TestDeauthFloodRule_BelowThreshold(t *testing.T) {
	rule := newDeauthFloodRuleForTest(t, 5, 10*time.Second)
	base := time.Unix(100, 0)

	for i := range 4 {
		events := rule.Process(deauthFrame(t, base.Add(time.Duration(i)*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
		if len(events) != 0 {
			t.Fatalf("frame %d: got %d events, want 0", i, len(events))
		}
	}
}

func TestDeauthFloodRule_ThresholdReached(t *testing.T) {
	rule := newDeauthFloodRuleForTest(t, 5, 10*time.Second)
	base := time.Unix(100, 0)

	var events []*SecurityEvent
	for i := range 5 {
		events = rule.Process(deauthFrame(t, base.Add(time.Duration(i)*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].EventType != "deauth_flood" {
		t.Errorf("EventType = %q, want deauth_flood", events[0].EventType)
	}
	if events[0].Severity != SeverityCritical {
		t.Errorf("Severity = %v, want SeverityCritical", events[0].Severity)
	}
	if events[0].FrameCount != 5 {
		t.Errorf("FrameCount = %d, want 5", events[0].FrameCount)
	}
}

func TestDeauthFloodRule_IgnoresNonDeauth(t *testing.T) {
	rule := newDeauthFloodRuleForTest(t, 1, 10*time.Second)
	frame := deauthFrame(t, time.Unix(100, 0), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
	frame.FrameType = parser.FrameTypeBeacon

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 for non-deauth frame", len(events))
	}
}

func TestDeauthFloodRule_WindowExcludesOldFrames(t *testing.T) {
	rule := newDeauthFloodRuleForTest(t, 3, 10*time.Second)
	base := time.Unix(100, 0)

	rule.Process(deauthFrame(t, base, "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	rule.Process(deauthFrame(t, base.Add(time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))

	events := rule.Process(deauthFrame(t, base.Add(20*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 because old frames are outside window", len(events))
	}
}

func TestDeauthFloodRule_TracksDifferentSourcesSeparately(t *testing.T) {
	rule := newDeauthFloodRuleForTest(t, 3, 10*time.Second)
	base := time.Unix(100, 0)

	rule.Process(deauthFrame(t, base, "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	rule.Process(deauthFrame(t, base.Add(time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))

	events := rule.Process(deauthFrame(t, base.Add(2*time.Second), "66:77:88:99:aa:bb", "aa:bb:cc:dd:ee:ff"))
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 because sources are tracked separately", len(events))
	}
}

func TestDeauthFloodRule_BroadcastMetadata(t *testing.T) {
	rule := newDeauthFloodRuleForTest(t, 1, 10*time.Second)
	frame := deauthFrame(t, time.Unix(100, 0), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
	frame.DstMAC = mustDeauthMAC(t, "ff:ff:ff:ff:ff:ff")

	events := rule.Process(frame)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Metadata["broadcast"] != true {
		t.Errorf("broadcast metadata = %v, want true", events[0].Metadata["broadcast"])
	}
}

func newDeauthFloodRuleForTest(t *testing.T, threshold int, window time.Duration) *DeauthFloodRule {
	t.Helper()

	rule := &DeauthFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DeauthFlood: config.DeauthFloodConfig{
			Threshold: threshold,
			Window:    window,
		},
	})
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	return rule
}

func deauthFrame(t *testing.T, ts time.Time, src string, bssid string) *parser.ParsedFrame {
	t.Helper()

	return &parser.ParsedFrame{
		FrameType:  parser.FrameTypeDeauth,
		Timestamp:  ts,
		SrcMAC:     mustDeauthMAC(t, src),
		DstMAC:     mustDeauthMAC(t, "ff:ff:ff:ff:ff:ff"),
		BSSID:      mustDeauthMAC(t, bssid),
		Channel:    6,
		RSSI:       -45,
		ReasonCode: 7,
	}
}

func mustDeauthMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("failed to parse MAC %q: %v", value, err)
	}

	return mac
}
