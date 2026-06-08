package detector

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func TestUnauthorizedDeviceRule_InitDisabledAllowsEmptyProtectedBSSIDs(t *testing.T) {
	rule := &UnauthorizedDeviceRule{}

	err := rule.Init(config.DetectionConfig{
		UnauthorizedDevice: config.UnauthorizedDeviceConfig{
			Enabled: false,
		},
	})
	if err != nil {
		t.Fatalf("Init() failed for disabled rule: %v", err)
	}
}

func TestUnauthorizedDeviceRule_InitEnabledRequiresProtectedTarget(t *testing.T) {
	rule := &UnauthorizedDeviceRule{}

	err := rule.Init(config.DetectionConfig{
		UnauthorizedDevice: config.UnauthorizedDeviceConfig{
			Enabled: true,
		},
	})
	if err == nil {
		t.Fatal("Init() expected error for enabled rule without protected_bssid or protected_ssid")
	}

	if !strings.Contains(err.Error(), "protected_bssid or protected_ssid") {
		t.Fatalf("Init() error = %q, want protected target error", err.Error())
	}
}

func TestUnauthorizedDeviceRule_InitRejectsInvalidProtectedBSSID(t *testing.T) {
	rule := &UnauthorizedDeviceRule{}

	err := rule.Init(config.DetectionConfig{
		UnauthorizedDevice: config.UnauthorizedDeviceConfig{
			Enabled:         true,
			ProtectedBSSIDs: []string{"not-a-mac"},
		},
	})
	if err == nil {
		t.Fatal("Init() expected error for invalid protected BSSID")
	}
}

func TestUnauthorizedDeviceRule_InitRejectsInvalidWhitelistMAC(t *testing.T) {
	rule := &UnauthorizedDeviceRule{}

	err := rule.Init(config.DetectionConfig{
		UnauthorizedDevice: config.UnauthorizedDeviceConfig{
			Enabled:         true,
			ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
			Whitelist:       []string{"not-a-mac"},
		},
	})
	if err == nil {
		t.Fatal("Init() expected error for invalid whitelist MAC")
	}
}

func TestUnauthorizedDeviceRule_DisabledProducesNoEvents(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled: false,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("Process() returned %d events, want 0", len(events))
	}
}

func TestUnauthorizedDeviceRule_UnknownDeviceGeneratesEvent(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		Whitelist:       []string{"00:11:22:33:44:55"},
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)

	events := rule.Process(frame)
	if len(events) != 1 {
		t.Fatalf("Process() returned %d events, want 1", len(events))
	}

	ev := events[0]
	if ev.EventType != "unauthorized_device" {
		t.Errorf("EventType = %q, want unauthorized_device", ev.EventType)
	}
	if ev.Severity != SeverityWarning {
		t.Errorf("Severity = %v, want SeverityWarning", ev.Severity)
	}
	if ev.SrcMAC.String() != "66:77:88:99:aa:bb" {
		t.Errorf("SrcMAC = %s, want unknown client MAC", ev.SrcMAC)
	}
	if ev.BSSID.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("BSSID = %s, want protected BSSID", ev.BSSID)
	}
	if ev.Metadata["frame_type"] != "auth" {
		t.Errorf("frame_type metadata = %v, want auth", ev.Metadata["frame_type"])
	}
	if ev.Metadata["protected_target"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("protected_target metadata = %v, want protected BSSID", ev.Metadata["protected_target"])
	}
}

func TestUnauthorizedDeviceRule_WhitelistedDeviceDoesNotGenerateEvent(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		Whitelist:       []string{"66:77:88:99:aa:bb"},
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeAssocReq)

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("Process() returned %d events, want 0 for whitelisted client", len(events))
	}
}

func TestUnauthorizedDeviceRule_IgnoresUnprotectedBSSID(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)
	frame.BSSID = mustMACForUnauthorizedTest(t, "11:22:33:44:55:66")

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("Process() returned %d events, want 0 for unprotected BSSID", len(events))
	}
}

func TestUnauthorizedDeviceRule_IgnoresIrrelevantFrameType(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeBeacon)

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("Process() returned %d events, want 0 for beacon frame", len(events))
	}
}

func TestUnauthorizedDeviceRule_ProbeRequestIgnoredByDefault(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		AlertOnProbe:    false,
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeProbeRequest)

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("Process() returned %d events, want 0 when alert_on_probe=false", len(events))
	}
}

func TestUnauthorizedDeviceRule_ProbeRequestMatchesProtectedSSID(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		ProtectedSSIDs:  []string{"ProtectedNetwork"},
		AlertOnProbe:    true,
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeProbeRequest)
	frame.DstMAC = mustMACForUnauthorizedTest(t, "ff:ff:ff:ff:ff:ff")
	frame.BSSID = mustMACForUnauthorizedTest(t, "ff:ff:ff:ff:ff:ff")
	frame.SSID = "ProtectedNetwork"

	events := rule.Process(frame)
	if len(events) != 1 {
		t.Fatalf("Process() returned %d events, want 1 for probe request to protected SSID", len(events))
	}

	if events[0].Metadata["frame_type"] != "probe_request" {
		t.Errorf("frame_type metadata = %v, want probe_request", events[0].Metadata["frame_type"])
	}

	if events[0].Metadata["protected_target"] != "ProtectedNetwork" {
		t.Errorf("protected_target metadata = %v, want ProtectedNetwork", events[0].Metadata["protected_target"])
	}
}

func TestUnauthorizedDeviceRule_ProbeRequestIgnoresNonProtectedSSID(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		ProtectedSSIDs:  []string{"ProtectedNetwork"},
		AlertOnProbe:    true,
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeProbeRequest)
	frame.DstMAC = mustMACForUnauthorizedTest(t, "ff:ff:ff:ff:ff:ff")
	frame.BSSID = mustMACForUnauthorizedTest(t, "ff:ff:ff:ff:ff:ff")
	frame.SSID = "GuestNetwork"

	events := rule.Process(frame)
	if len(events) != 0 {
		t.Fatalf("Process() returned %d events, want 0 for non-protected SSID", len(events))
	}
}

func TestUnauthorizedDeviceRule_CooldownSuppressesRepeatedAlert(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		Cooldown:        5 * time.Minute,
	})

	first := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)
	first.Timestamp = time.Unix(100, 0)

	second := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)
	second.Timestamp = first.Timestamp.Add(time.Minute)

	firstEvents := rule.Process(first)
	if len(firstEvents) != 1 {
		t.Fatalf("first Process() returned %d events, want 1", len(firstEvents))
	}

	secondEvents := rule.Process(second)
	if len(secondEvents) != 0 {
		t.Fatalf("second Process() returned %d events, want 0 during cooldown", len(secondEvents))
	}
}

func TestUnauthorizedDeviceRule_AllowsAlertAfterCooldown(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		Cooldown:        5 * time.Minute,
	})

	first := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)
	first.Timestamp = time.Unix(100, 0)

	second := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)
	second.Timestamp = first.Timestamp.Add(6 * time.Minute)

	firstEvents := rule.Process(first)
	if len(firstEvents) != 1 {
		t.Fatalf("first Process() returned %d events, want 1", len(firstEvents))
	}

	secondEvents := rule.Process(second)
	if len(secondEvents) != 1 {
		t.Fatalf("second Process() returned %d events, want 1 after cooldown", len(secondEvents))
	}
}

func TestUnauthorizedDeviceRule_UsesDstMACWhenBSSIDMissing(t *testing.T) {
	rule := newUnauthorizedDeviceRuleForTest(t, config.UnauthorizedDeviceConfig{
		Enabled:         true,
		ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"},
		Cooldown:        5 * time.Minute,
	})

	frame := unauthorizedDeviceFrame(t, parser.FrameTypeAuth)
	frame.BSSID = nil
	frame.DstMAC = mustMACForUnauthorizedTest(t, "aa:bb:cc:dd:ee:ff")

	events := rule.Process(frame)
	if len(events) != 1 {
		t.Fatalf("Process() returned %d events, want 1 using DstMAC fallback", len(events))
	}
	if events[0].BSSID.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("BSSID = %s, want DstMAC fallback", events[0].BSSID)
	}
}

func newUnauthorizedDeviceRuleForTest(t *testing.T, cfg config.UnauthorizedDeviceConfig) *UnauthorizedDeviceRule {
	t.Helper()

	rule := &UnauthorizedDeviceRule{}
	err := rule.Init(config.DetectionConfig{
		UnauthorizedDevice: cfg,
	})
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	return rule
}

func unauthorizedDeviceFrame(t *testing.T, frameType parser.FrameType) *parser.ParsedFrame {
	t.Helper()

	return &parser.ParsedFrame{
		FrameType: frameType,
		Timestamp: time.Unix(100, 0),
		SrcMAC:    mustMACForUnauthorizedTest(t, "66:77:88:99:aa:bb"),
		DstMAC:    mustMACForUnauthorizedTest(t, "aa:bb:cc:dd:ee:ff"),
		BSSID:     mustMACForUnauthorizedTest(t, "aa:bb:cc:dd:ee:ff"),
		SSID:      "ProtectedNetwork",
		Channel:   6,
		RSSI:      -45,
	}
}

func mustMACForUnauthorizedTest(t *testing.T, value string) net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("failed to parse MAC %q: %v", value, err)
	}

	return mac
}
