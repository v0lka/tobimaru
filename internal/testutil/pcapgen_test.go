package testutil

import (
	"net"
	"testing"
)

func TestBuildBeaconPcap(t *testing.T) {
	data := BuildBeaconPcap(
		SSID("TestNet"),
		RSSI(-42),
		Channel(6),
		SeqNum(100),
		SrcMAC(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
		DstMAC(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		BSSID(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
	)
	if len(data) == 0 {
		t.Fatal("BuildBeaconPcap returned empty data")
	}
}

func TestBuildProbeReqPcap(t *testing.T) {
	data := BuildProbeReqPcap(SSID("MyWiFi"), Channel(1))
	if len(data) == 0 {
		t.Fatal("BuildProbeReqPcap returned empty data")
	}
}

func TestBuildDeauthPcap(t *testing.T) {
	data := BuildDeauthPcap(Reason(7), Channel(11))
	if len(data) == 0 {
		t.Fatal("BuildDeauthPcap returned empty data")
	}
}

func TestBuildDisassocPcap(t *testing.T) {
	data := BuildDisassocPcap(Reason(3))
	if len(data) == 0 {
		t.Fatal("BuildDisassocPcap returned empty data")
	}
}

func TestBuildAuthPcap(t *testing.T) {
	data := BuildAuthPcap()
	if len(data) == 0 {
		t.Fatal("BuildAuthPcap returned empty data")
	}
}

func TestBuildMultiFramePcap(t *testing.T) {
	data := BuildMultiFramePcap(SSID("Multi"), Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildMultiFramePcap returned empty data")
	}
}

func TestBuildDeauthFloodPcap(t *testing.T) {
	data := BuildDeauthFloodPcap(FloodCount(20), Reason(1), Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildDeauthFloodPcap returned empty data")
	}
}

func TestBuildDisassocFloodPcap(t *testing.T) {
	data := BuildDisassocFloodPcap(FloodCount(15), Reason(8))
	if len(data) == 0 {
		t.Fatal("BuildDisassocFloodPcap returned empty data")
	}
}

func TestBuildBeaconPcapDefaults(t *testing.T) {
	// Test with no options to exercise default values.
	data := BuildBeaconPcap()
	if len(data) == 0 {
		t.Fatal("BuildBeaconPcap with defaults returned empty data")
	}
}

func TestBuildDeauthFloodPcapDefault(t *testing.T) {
	// FloodCount defaults to 10.
	data := BuildDeauthFloodPcap()
	if len(data) == 0 {
		t.Fatal("BuildDeauthFloodPcap with defaults returned empty data")
	}
}

func TestChannelToFreq(t *testing.T) {
	tests := []struct {
		ch   int
		freq int
	}{
		{1, 2412},
		{6, 2437},
		{11, 2462},
		{13, 2472},
		{14, 2484},
		{36, 5180},
		{44, 5220},
		{165, 5825},
		{200, 2412 + (200-1)*5}, // fallback for unknown channel
	}
	for _, tc := range tests {
		got := channelToFreq(tc.ch)
		if got != tc.freq {
			t.Errorf("channelToFreq(%d) = %d, want %d", tc.ch, got, tc.freq)
		}
	}
}

func TestBuildRadioTap5GHz(t *testing.T) {
	// Exercise the 5GHz flag path in buildRadioTap.
	data := BuildBeaconPcap(Channel(36))
	if len(data) == 0 {
		t.Fatal("BuildBeaconPcap with 5GHz channel returned empty data")
	}
}

func TestOptionFunctions(t *testing.T) {
	// Verify all option functions apply without panicking.
	var o options
	SrcMAC(net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})(&o)
	DstMAC(net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})(&o)
	BSSID(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})(&o)
	SSID("test")(&o)
	Channel(11)(&o)
	RSSI(-80)(&o)
	Reason(7)(&o)
	SeqNum(42)(&o)
	FloodCount(5)(&o)

	if o.ssid != "test" {
		t.Errorf("SSID option not applied: %q", o.ssid)
	}
	if o.channel != 11 {
		t.Errorf("Channel option not applied: %d", o.channel)
	}
	if o.rssi != -80 {
		t.Errorf("RSSI option not applied: %d", o.rssi)
	}
	if o.reason != 7 {
		t.Errorf("Reason option not applied: %d", o.reason)
	}
	if o.seqNum != 42 {
		t.Errorf("SeqNum option not applied: %d", o.seqNum)
	}
	if o.floodCount != 5 {
		t.Errorf("FloodCount option not applied: %d", o.floodCount)
	}
}

func TestBuildBeaconNoSSID(t *testing.T) {
	// Test beacon with empty SSID (writeSSIDIE should skip).
	data := BuildBeaconPcap(SSID(""))
	if len(data) == 0 {
		t.Fatal("BuildBeaconPcap with empty SSID returned empty data")
	}
}

func TestBuildProbeRespPcap(t *testing.T) {
	data := BuildProbeRespPcap(SSID("ProbeNet"), Channel(11))
	if len(data) == 0 {
		t.Fatal("BuildProbeRespPcap returned empty data")
	}
}

func TestBuildAssocReqPcap(t *testing.T) {
	data := BuildAssocReqPcap(SSID("AssocNet"), Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildAssocReqPcap returned empty data")
	}
}

func TestBuildAssocRespPcap(t *testing.T) {
	data := BuildAssocRespPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildAssocRespPcap returned empty data")
	}
}

func TestBuildActionPcap(t *testing.T) {
	data := BuildActionPcap(Channel(1))
	if len(data) == 0 {
		t.Fatal("BuildActionPcap returned empty data")
	}
}

func TestBuildRTSPcap(t *testing.T) {
	data := BuildRTSPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildRTSPcap returned empty data")
	}
}

func TestBuildCTSPcap(t *testing.T) {
	data := BuildCTSPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildCTSPcap returned empty data")
	}
}

func TestBuildACKPcap(t *testing.T) {
	data := BuildACKPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildACKPcap returned empty data")
	}
}

func TestBuildDataPcap(t *testing.T) {
	data := BuildDataPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildDataPcap returned empty data")
	}
}

func TestBuildNullDataPcap(t *testing.T) {
	data := BuildNullDataPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildNullDataPcap returned empty data")
	}
}

func TestBuildQoSDataPcap(t *testing.T) {
	data := BuildQoSDataPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildQoSDataPcap returned empty data")
	}
}

func TestBuildReassocReqPcap(t *testing.T) {
	data := BuildReassocReqPcap(SSID("ReassocNet"), Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildReassocReqPcap returned empty data")
	}
}

func TestBuildReassocRespPcap(t *testing.T) {
	data := BuildReassocRespPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildReassocRespPcap returned empty data")
	}
}

func TestBuildBlockAckReqPcap(t *testing.T) {
	data := BuildBlockAckReqPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildBlockAckReqPcap returned empty data")
	}
}

func TestBuildBlockAckPcap(t *testing.T) {
	data := BuildBlockAckPcap(Channel(6))
	if len(data) == 0 {
		t.Fatal("BuildBlockAckPcap returned empty data")
	}
}
