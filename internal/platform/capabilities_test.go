package platform

import "testing"

func TestDetect_HasExpectedFields(t *testing.T) {
	caps := Detect()

	// Basic sanity: all fields should be zero or non-zero in a consistent way.
	if caps.MonitorMode && caps.ChannelHopping {
		if caps.MaxChannels < 0 {
			t.Error("MaxChannels should not be negative when MonitorMode and ChannelHopping are true")
		}
	}
}

func TestReportLimitations_AllSupported(t *testing.T) {
	caps := Capabilities{
		MonitorMode:    true,
		FrameInjection: true,
		ChannelHopping: true,
		MaxChannels:    0,
		SlowHopping:    false,
		SingleAdapter:  false,
	}

	lims := caps.ReportLimitations()
	if len(lims) != 0 {
		t.Errorf("got %d limitations, want none: %v", len(lims), lims)
	}
}

func TestReportLimitations_AllLimited(t *testing.T) {
	caps := Capabilities{
		MonitorMode:    false,
		FrameInjection: false,
		ChannelHopping: true, // still true, but MaxChannels=1
		MaxChannels:    1,
		SlowHopping:    true,
		SingleAdapter:  true,
	}

	lims := caps.ReportLimitations()
	if len(lims) == 0 {
		t.Error("got no limitations, want some")
	}

	// Check specific limitation messages exist.
	found := map[string]bool{}
	for _, l := range lims {
		found[l] = true
	}

	want := []string{
		"monitor mode is not available",
		"frame injection is not supported",
		"single channel only; full channel hopping is not available",
		"channel switching has high overhead; increase dwell time",
		"single WiFi adapter; cannot operate in monitor and managed mode simultaneously",
	}
	for _, w := range want {
		if !found[w] {
			t.Errorf("expected limitation %q not found in: %v", w, lims)
		}
	}
}
