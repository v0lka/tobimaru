package detector

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/testutil"
)

func TestDeauthFloodRule_PcapIntegration_Positive(t *testing.T) {
	rule := newPcapDeauthRule(t, 10)

	data := testutil.BuildDeauthFloodPcap(
		testutil.SrcMAC(testMAC(t, "00:11:22:33:44:55")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.FloodCount(10),
		testutil.Channel(6),
		testutil.Reason(7),
	)

	events := processPcap(t, data, rule)
	requireOnePcapEvent(t, events, "deauth_flood")
}

func TestDeauthFloodRule_PcapIntegration_Negative(t *testing.T) {
	rule := newPcapDeauthRule(t, 10)

	data := testutil.BuildBeaconPcap(
		testutil.SSID("NormalNetwork"),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	requireNoPcapEvents(t, processPcap(t, data, rule))
}

func TestDeauthFloodRule_PcapIntegration_EdgeBelowThreshold(t *testing.T) {
	rule := newPcapDeauthRule(t, 10)

	data := testutil.BuildDeauthFloodPcap(
		testutil.SrcMAC(testMAC(t, "00:11:22:33:44:55")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.FloodCount(9),
		testutil.Channel(6),
		testutil.Reason(7),
	)

	requireNoPcapEvents(t, processPcap(t, data, rule))
}

func TestDisassocFloodRule_PcapIntegration_Positive(t *testing.T) {
	rule := newPcapDisassocRule(t, 10)

	data := testutil.BuildDisassocFloodPcap(
		testutil.SrcMAC(testMAC(t, "00:11:22:33:44:55")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.FloodCount(10),
		testutil.Channel(6),
		testutil.Reason(8),
	)

	events := processPcap(t, data, rule)
	requireOnePcapEvent(t, events, "disassoc_flood")
}

func TestDisassocFloodRule_PcapIntegration_Negative(t *testing.T) {
	rule := newPcapDisassocRule(t, 10)

	data := testutil.BuildBeaconPcap(
		testutil.SSID("NormalNetwork"),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	requireNoPcapEvents(t, processPcap(t, data, rule))
}

func TestDisassocFloodRule_PcapIntegration_EdgeBelowThreshold(t *testing.T) {
	rule := newPcapDisassocRule(t, 10)

	data := testutil.BuildDisassocFloodPcap(
		testutil.SrcMAC(testMAC(t, "00:11:22:33:44:55")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.FloodCount(9),
		testutil.Channel(6),
		testutil.Reason(8),
	)

	requireNoPcapEvents(t, processPcap(t, data, rule))
}

func TestBeaconFloodRule_PcapIntegration_Positive(t *testing.T) {
	rule := newPcapBeaconRule(t, 3)
	finishBeaconLearning(t, rule)

	events := make([]*SecurityEvent, 0, 3)

	for _, mac := range []string{
		"02:00:00:00:00:01",
		"02:00:00:00:00:02",
		"02:00:00:00:00:03",
	} {
		data := testutil.BuildBeaconPcap(
			testutil.SSID("FakeNetwork"),
			testutil.SrcMAC(testMAC(t, mac)),
			testutil.BSSID(testMAC(t, mac)),
			testutil.Channel(6),
			testutil.RSSI(-42),
		)

		events = append(events, processPcap(t, data, rule)...)
	}

	requireOnePcapEvent(t, events, "beacon_flood")
}

func TestBeaconFloodRule_PcapIntegration_Negative(t *testing.T) {
	rule := newPcapBeaconRule(t, 3)
	finishBeaconLearning(t, rule)

	for range 3 {
		data := testutil.BuildBeaconPcap(
			testutil.SSID("NormalNetwork"),
			testutil.SrcMAC(testMAC(t, "02:00:00:00:00:01")),
			testutil.BSSID(testMAC(t, "02:00:00:00:00:01")),
			testutil.Channel(6),
		)

		requireNoPcapEvents(t, processPcap(t, data, rule))
	}
}

func TestBeaconFloodRule_PcapIntegration_EdgeBelowThreshold(t *testing.T) {
	rule := newPcapBeaconRule(t, 3)
	finishBeaconLearning(t, rule)

	events := make([]*SecurityEvent, 0, 2)

	for _, mac := range []string{
		"02:00:00:00:00:01",
		"02:00:00:00:00:02",
	} {
		data := testutil.BuildBeaconPcap(
			testutil.SSID("FakeNetwork"),
			testutil.SrcMAC(testMAC(t, mac)),
			testutil.BSSID(testMAC(t, mac)),
			testutil.Channel(6),
		)

		events = append(events, processPcap(t, data, rule)...)
	}

	requireNoPcapEvents(t, events)
}

func TestEvilTwinRule_PcapIntegration_Positive(t *testing.T) {
	rule := newPcapEvilTwinRule(t, 80, 1)

	legitData := testutil.BuildBeaconPcap(
		testutil.SSID("CorpWiFi"),
		testutil.SrcMAC(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	legit := parseSingleTestPcapFrame(t, legitData)
	rule.Process(legit)
	finishEvilTwinLearning(t, rule, legit.Timestamp)

	twinData := testutil.BuildBeaconPcap(
		testutil.SSID("CorpWiFi"),
		testutil.SrcMAC(testMAC(t, "10:22:33:44:55:66")),
		testutil.BSSID(testMAC(t, "10:22:33:44:55:66")),
		testutil.Channel(11),
	)

	events := processPcap(t, twinData, rule)
	requireOnePcapEvent(t, events, "evil_twin")
}

func TestEvilTwinRule_PcapIntegration_Negative(t *testing.T) {
	rule := newPcapEvilTwinRule(t, 80, 1)

	legitData := testutil.BuildBeaconPcap(
		testutil.SSID("CorpWiFi"),
		testutil.SrcMAC(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	legit := parseSingleTestPcapFrame(t, legitData)
	rule.Process(legit)
	finishEvilTwinLearning(t, rule, legit.Timestamp)

	otherSSIDData := testutil.BuildBeaconPcap(
		testutil.SSID("GuestWiFi"),
		testutil.SrcMAC(testMAC(t, "10:22:33:44:55:66")),
		testutil.BSSID(testMAC(t, "10:22:33:44:55:66")),
		testutil.Channel(11),
	)

	requireNoPcapEvents(t, processPcap(t, otherSSIDData, rule))
}

func TestEvilTwinRule_PcapIntegration_EdgeBelowMinBeacons(t *testing.T) {
	rule := newPcapEvilTwinRule(t, 80, 2)

	legitData := testutil.BuildBeaconPcap(
		testutil.SSID("CorpWiFi"),
		testutil.SrcMAC(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	legit := parseSingleTestPcapFrame(t, legitData)
	rule.Process(legit)
	finishEvilTwinLearning(t, rule, legit.Timestamp)

	twinData := testutil.BuildBeaconPcap(
		testutil.SSID("CorpWiFi"),
		testutil.SrcMAC(testMAC(t, "10:22:33:44:55:66")),
		testutil.BSSID(testMAC(t, "10:22:33:44:55:66")),
		testutil.Channel(11),
	)

	requireNoPcapEvents(t, processPcap(t, twinData, rule))
}

func TestUnauthorizedDeviceRule_PcapIntegration_Positive(t *testing.T) {
	rule := newPcapUnauthorizedRule(t, []string{"00:11:22:33:44:55"})

	data := testutil.BuildAuthPcap(
		testutil.SrcMAC(testMAC(t, "66:77:88:99:aa:bb")),
		testutil.DstMAC(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	events := processPcap(t, data, rule)
	requireOnePcapEvent(t, events, "unauthorized_device")
}

func TestUnauthorizedDeviceRule_PcapIntegration_NegativeWhitelisted(t *testing.T) {
	rule := newPcapUnauthorizedRule(t, []string{"66:77:88:99:aa:bb"})

	data := testutil.BuildAssocReqPcap(
		testutil.SSID("CorpWiFi"),
		testutil.SrcMAC(testMAC(t, "66:77:88:99:aa:bb")),
		testutil.DstMAC(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	requireNoPcapEvents(t, processPcap(t, data, rule))
}

func TestUnauthorizedDeviceRule_PcapIntegration_EdgeCooldown(t *testing.T) {
	rule := newPcapUnauthorizedRule(t, nil)

	data := testutil.BuildAuthPcap(
		testutil.SrcMAC(testMAC(t, "66:77:88:99:aa:bb")),
		testutil.DstMAC(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.BSSID(testMAC(t, "aa:bb:cc:dd:ee:ff")),
		testutil.Channel(6),
	)

	requireOnePcapEvent(t, processPcap(t, data, rule), "unauthorized_device")
	requireNoPcapEvents(t, processPcap(t, data, rule))
}

func parseTestPcap(t *testing.T, data []byte) []*parser.ParsedFrame {
	t.Helper()

	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to open pcap: %v", err)
	}

	var frames []*parser.ParsedFrame
	packetSource := gopacket.NewPacketSource(
		&pcapReaderWrapper{reader: reader},
		layers.LayerTypeRadioTap,
	)

	for packet := range packetSource.Packets() {
		frame, err := parser.Parse(packet)
		if err != nil {
			continue
		}

		frames = append(frames, frame)
	}

	return frames
}

type pcapReaderWrapper struct {
	reader *pcapgo.Reader
}

func (w *pcapReaderWrapper) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return w.reader.ReadPacketData()
}

func processPcap(t *testing.T, data []byte, rule Rule) []*SecurityEvent {
	t.Helper()

	frames := parseTestPcap(t, data)
	events := make([]*SecurityEvent, 0, len(frames))
	for _, frame := range frames {
		events = append(events, rule.Process(frame)...)
	}

	return events
}

func parseSingleTestPcapFrame(t *testing.T, data []byte) *parser.ParsedFrame {
	t.Helper()

	frames := parseTestPcap(t, data)
	if len(frames) != 1 {
		t.Fatalf("got %d parsed frames, want 1", len(frames))
	}

	return frames[0]
}

func newPcapDeauthRule(t *testing.T, threshold int) *DeauthFloodRule {
	t.Helper()

	rule := &DeauthFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DeauthFlood: config.DeauthFloodConfig{
			Threshold: threshold,
			Window:    10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	return rule
}

func newPcapDisassocRule(t *testing.T, threshold int) *DisassocFloodRule {
	t.Helper()

	rule := &DisassocFloodRule{}
	err := rule.Init(config.DetectionConfig{
		DisassocFlood: config.DisassocFloodConfig{
			Threshold: threshold,
			Window:    10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	return rule
}

func newPcapBeaconRule(t *testing.T, threshold int) *BeaconFloodRule {
	t.Helper()

	rule := &BeaconFloodRule{}
	err := rule.Init(config.DetectionConfig{
		BeaconFlood: config.BeaconFloodConfig{
			Threshold:      threshold,
			Window:         10 * time.Second,
			LearningPeriod: time.Nanosecond,
		},
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	return rule
}

func newPcapEvilTwinRule(t *testing.T, scoreThreshold, minBeacons int) *EvilTwinRule {
	t.Helper()

	rule := &EvilTwinRule{}
	err := rule.Init(config.DetectionConfig{
		EvilTwin: config.EvilTwinConfig{
			ScoreThreshold: scoreThreshold,
			StaleTimeout:   5 * time.Minute,
			LearningPeriod: time.Nanosecond,
			MinBeacons:     minBeacons,
		},
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	return rule
}

func newPcapUnauthorizedRule(t *testing.T, whitelist []string) *UnauthorizedDeviceRule {
	t.Helper()

	rule := &UnauthorizedDeviceRule{}
	err := rule.Init(config.DetectionConfig{
		UnauthorizedDevice: config.UnauthorizedDeviceConfig{
			Enabled:         true,
			ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
			Whitelist:       whitelist,
			Cooldown:        5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	return rule
}

func finishBeaconLearning(t *testing.T, rule *BeaconFloodRule) {
	t.Helper()

	rule.mu.Lock()
	rule.startedAt = time.Now().Add(-time.Second)
	rule.mu.Unlock()
}

func finishEvilTwinLearning(t *testing.T, rule *EvilTwinRule, ts time.Time) {
	t.Helper()

	rule.mu.Lock()
	rule.startedAt = ts.Add(-time.Second)
	rule.mu.Unlock()
}

func testMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("failed to parse MAC %q: %v", value, err)
	}

	return mac
}

func requireOnePcapEvent(t *testing.T, events []*SecurityEvent, eventType string) {
	t.Helper()

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	if events[0].EventType != eventType {
		t.Fatalf("EventType = %q, want %q", events[0].EventType, eventType)
	}
}

func requireNoPcapEvents(t *testing.T, events []*SecurityEvent) {
	t.Helper()

	if len(events) != 0 {
		t.Fatalf("got %d events, want 0", len(events))
	}
}
