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

// TestDeauthFloodRule_RealCountAndDurationAfterCap verifies that FrameCount
// and Duration in the emitted event reflect the true flood intensity before the
// internal cap, not the truncated threshold subset. The internal timestamps
// slice is capped to threshold for memory safety, but the event metrics should
// report actual attack parameters.
func TestDeauthFloodRule_RealCountAndDurationAfterCap(t *testing.T) {
	rule := newDeauthFloodRuleForTest(t, 5, 10*time.Second)
	base := time.Unix(100, 0)

	frame := deauthFrame(t, base.Add(7*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
	key := floodKey(frame)

	rule.rule.mu.Lock()
	rule.rule.tracker[key] = &floodTracker{
		timestamps: []time.Time{
			base,
			base.Add(1 * time.Second),
			base.Add(2 * time.Second),
			base.Add(3 * time.Second),
			base.Add(4 * time.Second),
			base.Add(5 * time.Second),
			base.Add(6 * time.Second),
		},
		lastSeen: base.Add(6 * time.Second),
	}
	rule.rule.mu.Unlock()

	events := rule.Process(frame)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	// 7 pre-seeded + 1 new = 8 frames total in window; threshold=5
	if events[0].FrameCount != 8 {
		t.Fatalf("FrameCount = %d, want real count 8 (pre-cap)", events[0].FrameCount)
	}

	if events[0].Duration != 7*time.Second {
		t.Fatalf("Duration = %v, want real duration 7s (pre-cap)", events[0].Duration)
	}

	// Verify tracker still exists (post-emission reset) and timestamps are cleared.
	rule.rule.mu.Lock()
	tr := rule.rule.tracker[key]
	rule.rule.mu.Unlock()

	if tr == nil {
		t.Fatal("tracker entry was unexpectedly removed after event emission")
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

func TestDeauthFloodRule_InitRejectsInvalidThreshold(t *testing.T) {
	rule := &DeauthFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DeauthFlood: config.DeauthFloodConfig{
			Threshold: 0,
			Window:    10 * time.Second,
		},
	})
	if err == nil {
		t.Fatal("Init() expected error for threshold <= 0")
	}
}

func TestDeauthFloodRule_InitRejectsWindowBelowOneSecond(t *testing.T) {
	rule := &DeauthFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DeauthFlood: config.DeauthFloodConfig{
			Threshold: 5,
			Window:    500 * time.Millisecond,
		},
	})
	if err == nil {
		t.Fatal("Init() expected error for window below 1s")
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

func deauthFrame(t *testing.T, ts time.Time, src, bssid string) *parser.ParsedFrame {
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
