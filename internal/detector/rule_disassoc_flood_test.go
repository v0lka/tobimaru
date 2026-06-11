package detector

import (
	"net"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func TestDisassocFloodRule_BelowThreshold(t *testing.T) {
	rule := newDisassocFloodRuleForTest(t, 5, 10*time.Second)
	base := time.Unix(100, 0)

	for i := range 4 {
		events := rule.Process(disassocFrame(t, base.Add(time.Duration(i)*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
		if len(events) != 0 {
			t.Fatalf("frame %d: got %d events, want 0", i, len(events))
		}
	}
}

func TestDisassocFloodRule_ThresholdReached(t *testing.T) {
	rule := newDisassocFloodRuleForTest(t, 5, 10*time.Second)
	base := time.Unix(100, 0)

	var events []*SecurityEvent
	for i := range 5 {
		events = rule.Process(disassocFrame(t, base.Add(time.Duration(i)*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].EventType != "disassoc_flood" {
		t.Errorf("EventType = %q, want disassoc_flood", events[0].EventType)
	}
	if events[0].Severity != SeverityCritical {
		t.Errorf("Severity = %v, want SeverityCritical", events[0].Severity)
	}
	if events[0].FrameCount != 5 {
		t.Errorf("FrameCount = %d, want 5", events[0].FrameCount)
	}
}

func TestDisassocFloodRule_IgnoresNonDisassoc(t *testing.T) {
	rule := newDisassocFloodRuleForTest(t, 1, 10*time.Second)
	frame := disassocFrame(t, time.Unix(100, 0), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
	frame.FrameType = parser.FrameTypeDeauth

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 for non-disassoc frame", len(events))
	}
}

func TestDisassocFloodRule_WindowExcludesOldFrames(t *testing.T) {
	rule := newDisassocFloodRuleForTest(t, 3, 10*time.Second)
	base := time.Unix(100, 0)

	rule.Process(disassocFrame(t, base, "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	rule.Process(disassocFrame(t, base.Add(time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))

	events := rule.Process(disassocFrame(t, base.Add(20*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 because old frames are outside window", len(events))
	}
}

func TestDisassocFloodRule_TracksDifferentSourcesSeparately(t *testing.T) {
	rule := newDisassocFloodRuleForTest(t, 3, 10*time.Second)
	base := time.Unix(100, 0)

	rule.Process(disassocFrame(t, base, "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))
	rule.Process(disassocFrame(t, base.Add(time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"))

	events := rule.Process(disassocFrame(t, base.Add(2*time.Second), "66:77:88:99:aa:bb", "aa:bb:cc:dd:ee:ff"))
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 because sources are tracked separately", len(events))
	}
}

// TestDisassocFloodRule_RealCountAndDurationAfterCap verifies that FrameCount
// and Duration in the emitted event reflect the true flood intensity before the
// internal cap, not the truncated threshold subset. Uses the same shared
// floodRule.process code path as DeauthFloodRule.
func TestDisassocFloodRule_RealCountAndDurationAfterCap(t *testing.T) {
	rule := newDisassocFloodRuleForTest(t, 5, 10*time.Second)
	base := time.Unix(100, 0)

	frame := disassocFrame(t, base.Add(7*time.Second), "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
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
}

func TestDisassocFloodRule_InitRejectsInvalidThreshold(t *testing.T) {
	rule := &DisassocFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DisassocFlood: config.DisassocFloodConfig{
			Threshold: 0,
			Window:    10 * time.Second,
		},
	})
	if err == nil {
		t.Fatal("Init() expected error for threshold <= 0")
	}
}

func TestDisassocFloodRule_InitRejectsWindowBelowOneSecond(t *testing.T) {
	rule := &DisassocFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DisassocFlood: config.DisassocFloodConfig{
			Threshold: 5,
			Window:    500 * time.Millisecond,
		},
	})
	if err == nil {
		t.Fatal("Init() expected error for window below 1s")
	}
}

func newDisassocFloodRuleForTest(t *testing.T, threshold int, window time.Duration) *DisassocFloodRule {
	t.Helper()

	rule := &DisassocFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DisassocFlood: config.DisassocFloodConfig{
			Threshold: threshold,
			Window:    window,
		},
	})
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	return rule
}

func disassocFrame(t *testing.T, ts time.Time, src, bssid string) *parser.ParsedFrame {
	t.Helper()

	return &parser.ParsedFrame{
		FrameType:  parser.FrameTypeDisassoc,
		Timestamp:  ts,
		SrcMAC:     mustDisassocMAC(t, src),
		DstMAC:     mustDisassocMAC(t, "ff:ff:ff:ff:ff:ff"),
		BSSID:      mustDisassocMAC(t, bssid),
		Channel:    6,
		RSSI:       -45,
		ReasonCode: 8,
	}
}

func mustDisassocMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("failed to parse MAC %q: %v", value, err)
	}

	return mac
}
