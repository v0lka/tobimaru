package detector

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func TestBeaconFloodRule_BelowThreshold(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      5,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	base := time.Unix(100, 0)

	for i := range 4 {
		frame := beaconFloodFrame(t, i, 6, base.Add(time.Duration(i)*time.Second))
		events := rule.Process(frame)
		if len(events) != 0 {
			t.Fatalf("frame %d: got %d events, want 0", i, len(events))
		}
	}
}

func TestBeaconFloodRule_ThresholdReached(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      5,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	base := time.Unix(100, 0)

	finishBeaconFloodLearningForTest(t, rule, base)

	var events []*SecurityEvent
	var lastFrame *parser.ParsedFrame

	for i := range 5 {
		lastFrame = beaconFloodFrame(t, i, 6, base.Add(time.Duration(i)*time.Second))
		events = rule.Process(lastFrame)
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	ev := events[0]

	if ev.SrcMAC.String() != lastFrame.SrcMAC.String() {
		t.Errorf("SrcMAC = %s, want %s", ev.SrcMAC, lastFrame.SrcMAC)
	}

	if ev.BSSID.String() != lastFrame.BSSID.String() {
		t.Errorf("BSSID = %s, want %s", ev.BSSID, lastFrame.BSSID)
	}

	if ev.EventType != "beacon_flood" {
		t.Errorf("EventType = %q, want beacon_flood", ev.EventType)
	}
	if ev.Severity != SeverityWarning {
		t.Errorf("Severity = %v, want SeverityWarning", ev.Severity)
	}
	if ev.Channel != 6 {
		t.Errorf("Channel = %d, want 6", ev.Channel)
	}
	if ev.Metadata["new_bssid_count"] != 5 {
		t.Errorf("new_bssid_count = %v, want 5", ev.Metadata["new_bssid_count"])
	}
}

func TestBeaconFloodRule_InitRejectsWindowBelowOneSecond(t *testing.T) {
	rule := &BeaconFloodRule{}

	err := rule.Init(config.DetectionConfig{
		BeaconFlood: config.BeaconFloodConfig{
			Threshold:      5,
			Window:         500 * time.Millisecond,
			LearningPeriod: time.Second,
		},
	})

	if err == nil {
		t.Fatal("Init() expected error for window below 1s")
	}
}

func TestBeaconFloodRule_IgnoresNonBeacon(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      1,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	frame := beaconFloodFrame(t, 0, 6, time.Unix(100, 0))
	frame.FrameType = parser.FrameTypeProbeResponse

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 for non-beacon frame", len(events))
	}
}

func TestBeaconFloodRule_KnownBSSIDDoesNotCountAsNew(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      2,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	base := time.Unix(100, 0)

	frame1 := beaconFloodFrame(t, 1, 6, base)
	frame2 := beaconFloodFrame(t, 1, 6, base.Add(time.Second))

	if events := rule.Process(frame1); len(events) != 0 {
		t.Fatalf("first frame got %d events, want 0", len(events))
	}

	if events := rule.Process(frame2); len(events) != 0 {
		t.Fatalf("duplicate BSSID got %d events, want 0", len(events))
	}
}

func TestBeaconFloodRule_WindowResetPreventsOldFramesFromCounting(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      3,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	base := time.Unix(100, 0)

	for i := range 2 {
		frame := beaconFloodFrame(t, i, 6, base.Add(time.Duration(i)*time.Second))
		if events := rule.Process(frame); len(events) != 0 {
			t.Fatalf("frame %d got %d events, want 0", i, len(events))
		}
	}

	late := beaconFloodFrame(t, 99, 6, base.Add(11*time.Second))
	events := rule.Process(late)
	if len(events) != 0 {
		t.Fatalf("late frame got %d events, want 0 after window reset", len(events))
	}
}

func TestBeaconFloodRule_TracksChannelsSeparately(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      3,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	base := time.Unix(100, 0)

	rule.Process(beaconFloodFrame(t, 1, 1, base))
	rule.Process(beaconFloodFrame(t, 2, 1, base.Add(time.Second)))

	events := rule.Process(beaconFloodFrame(t, 3, 6, base.Add(2*time.Second)))
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 because channels are tracked separately", len(events))
	}
}

func TestBeaconFloodRule_LearningPeriodSuppressesAlerts(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      3,
		Window:         10 * time.Second,
		LearningPeriod: 60 * time.Second,
	})

	base := time.Unix(100, 0)

	for i := range 5 {
		frame := beaconFloodFrame(t, i, 6, base.Add(time.Duration(i)*time.Second))
		events := rule.Process(frame)
		if len(events) != 0 {
			t.Fatalf("frame %d during learning period got %d events, want 0", i, len(events))
		}
	}
}

func TestBeaconFloodRule_KnownDuringLearningPeriodIgnoredLater(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      2,
		Window:         10 * time.Second,
		LearningPeriod: 10 * time.Second,
	})

	base := time.Unix(100, 0)

	known := beaconFloodFrame(t, 1, 6, base)
	rule.Process(known)

	afterLearning := beaconFloodFrame(t, 1, 6, base.Add(11*time.Second))
	if events := rule.Process(afterLearning); len(events) != 0 {
		t.Fatalf("known BSSID after learning got %d events, want 0", len(events))
	}

	newOne := beaconFloodFrame(t, 2, 6, base.Add(12*time.Second))
	if events := rule.Process(newOne); len(events) != 0 {
		t.Fatalf("only one new BSSID got %d events, want 0", len(events))
	}
}

func TestBeaconFloodRule_MetadataContainsSampleSSIDsAndCommonRSSI(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      3,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	base := time.Unix(100, 0)

	finishBeaconFloodLearningForTest(t, rule, base)

	var events []*SecurityEvent
	for i := range 3 {
		frame := beaconFloodFrame(t, i, 6, base.Add(time.Duration(i)*time.Second))
		frame.RSSI = -40
		frame.SSID = fmt.Sprintf("FakeNetwork-%d", i)
		events = rule.Process(frame)
	}

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	if events[0].Metadata["common_rssi"] != -40 {
		t.Errorf("common_rssi = %v, want -40", events[0].Metadata["common_rssi"])
	}

	sampleSSIDs, ok := events[0].Metadata["sample_ssids"].([]string)
	if !ok {
		t.Fatalf("sample_ssids has type %T, want []string", events[0].Metadata["sample_ssids"])
	}
	if len(sampleSSIDs) == 0 {
		t.Fatal("sample_ssids is empty, want at least one SSID")
	}
}

func TestBeaconFloodRule_CleanupStaleRemovesOldState(t *testing.T) {
	rule := newBeaconFloodRuleForTest(t, config.BeaconFloodConfig{
		Threshold:      50,
		Window:         10 * time.Second,
		LearningPeriod: time.Nanosecond,
	})

	old := time.Unix(100, 0)

	finishBeaconFloodLearningForTest(t, rule, old)

	frame := beaconFloodFrame(t, 1, 6, old)

	rule.Process(frame)

	rule.mu.Lock()
	if len(rule.channels) != 1 {
		t.Fatalf("channels len = %d, want 1 before cleanup", len(rule.channels))
	}
	rule.mu.Unlock()

	rule.mu.Lock()
	rule.cleanupStale(old.Add(2 * time.Hour))
	rule.mu.Unlock()

	rule.mu.Lock()
	defer rule.mu.Unlock()

	if len(rule.channels) != 0 {
		t.Fatalf("channels len = %d, want 0 after cleanup", len(rule.channels))
	}
}

func newBeaconFloodRuleForTest(t *testing.T, cfg config.BeaconFloodConfig) *BeaconFloodRule {
	t.Helper()

	rule := &BeaconFloodRule{}
	err := rule.Init(config.DetectionConfig{
		BeaconFlood: cfg,
	})
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	return rule
}

func finishBeaconFloodLearningForTest(t *testing.T, rule *BeaconFloodRule, now time.Time) {
	t.Helper()

	rule.mu.Lock()
	rule.startedAt = now.Add(-time.Second)
	rule.mu.Unlock()
}

func beaconFloodFrame(t *testing.T, id, channel int, ts time.Time) *parser.ParsedFrame {
	t.Helper()

	return &parser.ParsedFrame{
		FrameType:      parser.FrameTypeBeacon,
		Timestamp:      ts,
		SrcMAC:         beaconFloodMAC(t, id),
		DstMAC:         mustBeaconFloodMAC(t, "ff:ff:ff:ff:ff:ff"),
		BSSID:          beaconFloodMAC(t, id),
		SSID:           fmt.Sprintf("FakeNetwork-%d", id),
		Channel:        channel,
		RSSI:           -45,
		BeaconInterval: 100,
		Capability:     0x0431,
	}
}

func beaconFloodMAC(t *testing.T, id int) net.HardwareAddr {
	t.Helper()

	value := fmt.Sprintf("02:00:00:00:%02x:%02x", id/256, id%256)
	return mustBeaconFloodMAC(t, value)
}

func mustBeaconFloodMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("failed to parse MAC %q: %v", value, err)
	}

	return mac
}
