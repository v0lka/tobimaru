package detector

import (
	"net"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func TestEvilTwinRule_IgnoresNonBeaconAndNonProbeResponse(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     1,
	})

	frame := evilTwinFrame(t, parser.FrameTypeProbeRequest, time.Unix(100, 0), "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, nil)

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 for irrelevant frame type", len(events))
	}
}

func TestEvilTwinRule_IgnoresEmptySSID(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     1,
	})

	frame := evilTwinFrame(t, parser.FrameTypeBeacon, time.Unix(100, 0), "", "aa:bb:cc:dd:ee:ff", 6, nil)

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 for empty SSID", len(events))
	}
}

func TestEvilTwinRule_SingleBSSIDDoesNotGenerateEvent(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     1,
	})

	frame := evilTwinFrame(t, parser.FrameTypeBeacon, time.Unix(100, 0), "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, evilTwinRSN(1))

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 for single BSSID", len(events))
	}
}

func TestEvilTwinRule_DetectsDifferentBSSIDAndChannel(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     1,
	})

	base := time.Unix(100, 0)

	rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base, "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, evilTwinRSN(1)))
	events := rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(time.Second), "CorpWiFi", "11:22:33:44:55:66", 11, evilTwinRSN(1)))

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	ev := events[0]
	if ev.EventType != "evil_twin" {
		t.Errorf("EventType = %q, want evil_twin", ev.EventType)
	}
	if ev.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want SeverityCritical", ev.Severity)
	}
	if ev.SSID != "CorpWiFi" {
		t.Errorf("SSID = %q, want CorpWiFi", ev.SSID)
	}
	if ev.Metadata["score"] != 80 {
		t.Errorf("score = %v, want 80", ev.Metadata["score"])
	}
}

func TestEvilTwinRule_DetectsRSNMismatch(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     1,
	})

	base := time.Unix(100, 0)

	rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base, "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, evilTwinRSN(1)))
	events := rule.Process(evilTwinFrame(t, parser.FrameTypeProbeResponse, base.Add(time.Second), "CorpWiFi", "11:22:33:44:55:66", 6, evilTwinRSN(2)))

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1 for RSN mismatch", len(events))
	}

	mismatches, ok := events[0].Metadata["ie_mismatch"].([]string)
	if !ok {
		t.Fatalf("ie_mismatch type = %T, want []string", events[0].Metadata["ie_mismatch"])
	}
	if !containsString(mismatches, "rsn") {
		t.Fatalf("ie_mismatch = %v, want rsn", mismatches)
	}
}

func TestEvilTwinRule_MinBeaconsIsRespected(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     3,
	})

	base := time.Unix(100, 0)

	for i := range 3 {
		rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(time.Duration(i)*time.Second), "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, evilTwinRSN(1)))
	}

	if events := rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(3*time.Second), "CorpWiFi", "11:22:33:44:55:66", 11, evilTwinRSN(1))); len(events) != 0 {
		t.Fatalf("got %d events, want 0 before candidate reaches min_beacons", len(events))
	}

	rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(4*time.Second), "CorpWiFi", "11:22:33:44:55:66", 11, evilTwinRSN(1)))
	events := rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(5*time.Second), "CorpWiFi", "11:22:33:44:55:66", 11, evilTwinRSN(1)))

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1 after candidate reaches min_beacons", len(events))
	}
}

func TestEvilTwinRule_LearningPeriodSuppressesEvents(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Minute,
		MinBeacons:     1,
	})

	base := time.Unix(100, 0)

	rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base, "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, evilTwinRSN(1)))
	events := rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(time.Second), "CorpWiFi", "11:22:33:44:55:66", 11, evilTwinRSN(1)))

	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 during learning period", len(events))
	}
}

func TestEvilTwinRule_SuppressesDuplicatePairWithinStaleTimeout(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   5 * time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     1,
	})

	base := time.Unix(100, 0)

	rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base, "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, evilTwinRSN(1)))

	first := rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(time.Second), "CorpWiFi", "11:22:33:44:55:66", 11, evilTwinRSN(1)))
	if len(first) != 1 {
		t.Fatalf("first detection got %d events, want 1", len(first))
	}

	second := rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base.Add(2*time.Second), "CorpWiFi", "11:22:33:44:55:66", 11, evilTwinRSN(1)))
	if len(second) != 0 {
		t.Fatalf("duplicate detection got %d events, want 0", len(second))
	}
}

func TestEvilTwinRule_CleanupStaleRemovesOldAPs(t *testing.T) {
	rule := newEvilTwinRuleForTest(t, config.EvilTwinConfig{
		ScoreThreshold: 80,
		StaleTimeout:   time.Minute,
		LearningPeriod: time.Nanosecond,
		MinBeacons:     1,
	})

	base := time.Unix(100, 0)
	rule.Process(evilTwinFrame(t, parser.FrameTypeBeacon, base, "CorpWiFi", "aa:bb:cc:dd:ee:ff", 6, evilTwinRSN(1)))

	rule.mu.Lock()
	rule.cleanupStale(base.Add(2 * time.Minute))
	got := len(rule.apsBySSID)
	rule.mu.Unlock()

	if got != 0 {
		t.Fatalf("apsBySSID len = %d, want 0 after cleanup", got)
	}
}

func newEvilTwinRuleForTest(t *testing.T, cfg config.EvilTwinConfig) *EvilTwinRule {
	t.Helper()

	rule := &EvilTwinRule{}
	err := rule.Init(config.DetectionConfig{
		EvilTwin: cfg,
	})
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	return rule
}

func evilTwinFrame(
	t *testing.T,
	frameType parser.FrameType,
	ts time.Time,
	ssid string,
	bssid string,
	channel int,
	ies map[uint8][]byte,
) *parser.ParsedFrame {
	t.Helper()

	return &parser.ParsedFrame{
		FrameType:      frameType,
		Timestamp:      ts,
		SrcMAC:         mustEvilTwinMAC(t, bssid),
		DstMAC:         mustEvilTwinMAC(t, "ff:ff:ff:ff:ff:ff"),
		BSSID:          mustEvilTwinMAC(t, bssid),
		SSID:           ssid,
		Channel:        channel,
		RSSI:           -40,
		InfoElements:   ies,
		Capability:     0x0431,
		BeaconInterval: 100,
	}
}

func evilTwinRSN(value byte) map[uint8][]byte {
	return map[uint8][]byte{
		48: {value, 0x01, 0x02, 0x03},
	}
}

func mustEvilTwinMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("failed to parse MAC %q: %v", value, err)
	}

	return mac
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}
