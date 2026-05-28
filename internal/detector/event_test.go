package detector

import (
	"net"
	"testing"
	"time"
)

func TestSeverityOrdering(t *testing.T) {
	severities := []Severity{SeverityInfo, SeverityWarning, SeverityCritical}
	for i := 1; i < len(severities); i++ {
		if severities[i] <= severities[i-1] {
			t.Errorf("expected %s > %s", severities[i].String(), severities[i-1].String())
		}
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown(99)"},
	}

	for _, tt := range tests {
		got := tt.sev.String()
		if got != tt.expected {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tt.sev), got, tt.expected)
		}
	}
}

func TestNewEvent(t *testing.T) {
	ts := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	ev := NewEvent(ts, "deauth_flood", SeverityCritical)

	if ev.Timestamp != ts {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, ts)
	}
	if ev.EventType != "deauth_flood" {
		t.Errorf("EventType = %q, want %q", ev.EventType, "deauth_flood")
	}
	if ev.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want %v", ev.Severity, SeverityCritical)
	}
	if ev.Metadata == nil {
		t.Error("Metadata should not be nil after NewEvent")
	}
}

func TestEventFields(t *testing.T) {
	ev := NewEvent(time.Now(), "evil_twin", SeverityWarning)
	ev.SrcMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ev.DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ev.BSSID = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ev.SSID = "TestNetwork"
	ev.Channel = 6
	ev.RSSI = -45
	ev.FrameCount = 10
	ev.Duration = 5 * time.Second
	ev.Description = "Evil Twin AP detected"
	ev.Metadata["bssid_real"] = "00:11:22:33:44:55"

	if ev.SrcMAC.String() != "00:11:22:33:44:55" {
		t.Errorf("SrcMAC = %s, want 00:11:22:33:44:55", ev.SrcMAC)
	}
	if ev.DstMAC.String() != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("DstMAC = %s, want ff:ff:ff:ff:ff:ff", ev.DstMAC)
	}
	if ev.BSSID.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("BSSID = %s, want aa:bb:cc:dd:ee:ff", ev.BSSID)
	}
	if ev.SSID != "TestNetwork" {
		t.Errorf("SSID = %q, want TestNetwork", ev.SSID)
	}
	if ev.Channel != 6 {
		t.Errorf("Channel = %d, want 6", ev.Channel)
	}
	if ev.RSSI != -45 {
		t.Errorf("RSSI = %d, want -45", ev.RSSI)
	}
	if ev.FrameCount != 10 {
		t.Errorf("FrameCount = %d, want 10", ev.FrameCount)
	}
	if ev.Duration != 5*time.Second {
		t.Errorf("Duration = %v, want 5s", ev.Duration)
	}
	if ev.Description != "Evil Twin AP detected" {
		t.Errorf("Description = %q, want 'Evil Twin AP detected'", ev.Description)
	}
	if ev.Metadata["bssid_real"] != "00:11:22:33:44:55" {
		t.Errorf("Metadata[bssid_real] = %v", ev.Metadata["bssid_real"])
	}
}

func TestEventString(t *testing.T) {
	ev := NewEvent(time.Now(), "deauth_flood", SeverityCritical)
	ev.SrcMAC, _ = net.ParseMAC("00:11:22:33:44:55")
	ev.Channel = 6
	ev.Description = "Deauthentication flood detected"

	str := ev.String()
	if str == "" {
		t.Error("Event.String() should not be empty")
	}
}

func TestEventZeroMAC(t *testing.T) {
	ev := NewEvent(time.Now(), "beacon_flood", SeverityWarning)

	// Zero-value MAC is nil, should be handled gracefully by String()
	str := ev.String()
	if str == "" {
		t.Error("Event.String() with nil MAC should not panic or return empty")
	}
}
