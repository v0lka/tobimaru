package parser

import (
	"os"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/vkochetkov/tobimaru/internal/testutil"
)

// TestParseBeacon verifies that a beacon frame is correctly parsed with SSID,
// RSSI, channel, and MAC addresses.
func TestParseBeacon(t *testing.T) {
	ssidStr := "TestNetwork"
	pcapData := testutil.BuildBeaconPcap(
		testutil.SSID(ssidStr),
		testutil.RSSI(-42),
		testutil.Channel(6),
		testutil.SeqNum(100),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeBeacon {
		t.Errorf("expected FrameTypeBeacon, got %v", frame.FrameType)
	}
	if frame.SSID != ssidStr {
		t.Errorf("expected SSID %q, got %q", ssidStr, frame.SSID)
	}
	if frame.RSSI != -42 {
		t.Errorf("expected RSSI -42, got %d", frame.RSSI)
	}
	if frame.Channel != 6 {
		t.Errorf("expected channel 6, got %d", frame.Channel)
	}
	if frame.SequenceNum != 100 {
		t.Errorf("expected sequence 100, got %d", frame.SequenceNum)
	}
	if len(frame.SrcMAC) != 6 {
		t.Errorf("expected source MAC, got %v", frame.SrcMAC)
	}
	if len(frame.BSSID) != 6 {
		t.Errorf("expected BSSID, got %v", frame.BSSID)
	}
	if frame.BeaconInterval != 100 {
		t.Errorf("expected beacon interval 100, got %d", frame.BeaconInterval)
	}
}

// TestParseProbeRequest verifies probe request parsing.
func TestParseProbeRequest(t *testing.T) {
	pcapData := testutil.BuildProbeReqPcap(
		testutil.SSID("MyWiFi"),
		testutil.RSSI(-55),
		testutil.Channel(1),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeProbeRequest {
		t.Errorf("expected FrameTypeProbeRequest, got %v", frame.FrameType)
	}
	if frame.SSID != "MyWiFi" {
		t.Errorf("expected SSID MyWiFi, got %q", frame.SSID)
	}
	if frame.RSSI != -55 {
		t.Errorf("expected RSSI -55, got %d", frame.RSSI)
	}
	if frame.Channel != 1 {
		t.Errorf("expected channel 1, got %d", frame.Channel)
	}
}

// TestParseDeauth verifies deauthentication frame parsing including reason code.
func TestParseDeauth(t *testing.T) {
	pcapData := testutil.BuildDeauthPcap(
		testutil.Reason(7),
		testutil.RSSI(-60),
		testutil.Channel(11),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeDeauth {
		t.Errorf("expected FrameTypeDeauth, got %v", frame.FrameType)
	}
	if frame.ReasonCode != 7 {
		t.Errorf("expected reason code 7, got %d", frame.ReasonCode)
	}
	if frame.RSSI != -60 {
		t.Errorf("expected RSSI -60, got %d", frame.RSSI)
	}
}

// TestParseDisassoc verifies disassociation frame parsing.
func TestParseDisassoc(t *testing.T) {
	pcapData := testutil.BuildDisassocPcap(
		testutil.Reason(3),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeDisassoc {
		t.Errorf("expected FrameTypeDisassoc, got %v", frame.FrameType)
	}
	if frame.ReasonCode != 3 {
		t.Errorf("expected reason code 3, got %d", frame.ReasonCode)
	}
}

// TestParseAuth verifies authentication frame parsing.
func TestParseAuth(t *testing.T) {
	pcapData := testutil.BuildAuthPcap()

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeAuth {
		t.Errorf("expected FrameTypeAuth, got %v", frame.FrameType)
	}
	if frame.AuthSeq != 1 {
		t.Errorf("expected auth seq 1, got %d", frame.AuthSeq)
	}
}

// TestParseMultiFrame verifies parsing multiple frames from a single pcap.
func TestParseMultiFrame(t *testing.T) {
	pcapData := testutil.BuildMultiFramePcap(
		testutil.SSID("MultiSSID"),
	)

	frames := parsePcapFrames(t, pcapData)
	if len(frames) < 3 {
		t.Fatalf("expected at least 3 frames, got %d", len(frames))
	}

	expected := []FrameType{FrameTypeBeacon, FrameTypeProbeRequest, FrameTypeDeauth}
	for i, ft := range expected {
		if i >= len(frames) {
			break
		}
		if frames[i].FrameType != ft {
			t.Errorf("frame %d: expected %v, got %v", i, ft, frames[i].FrameType)
		}
	}
}

// TestFrameTypeStrings verifies that all frame types have non-empty string representations.
func TestFrameTypeStrings(t *testing.T) {
	types := []FrameType{
		FrameTypeBeacon, FrameTypeProbeRequest, FrameTypeProbeResponse,
		FrameTypeAuth, FrameTypeDeauth, FrameTypeDisassoc,
		FrameTypeAssocReq, FrameTypeAssocResp,
		FrameTypeCTS, FrameTypeRTS, FrameTypeACK,
		FrameTypeData, FrameTypeNull, FrameTypeQoSData,
	}
	for _, ft := range types {
		if s := ft.String(); s == "" || s == "Unknown" {
			t.Errorf("FrameType %d has string %q", ft, s)
		}
	}
}

// TestIsManagementControlData checks the classification helper methods.
func TestIsManagementControlData(t *testing.T) {
	if !FrameTypeBeacon.IsManagement() {
		t.Error("beacon should be management")
	}
	if !FrameTypeDeauth.IsManagement() {
		t.Error("deauth should be management")
	}
	if !FrameTypeRTS.IsControl() {
		t.Error("RTS should be control")
	}
	if !FrameTypeData.IsData() {
		t.Error("data should be data")
	}
	if FrameTypeBeacon.IsControl() || FrameTypeBeacon.IsData() {
		t.Error("beacon should NOT be control or data")
	}
}

// TestFreqToChannel verifies channel frequency to channel number conversion.
func TestFreqToChannel(t *testing.T) {
	tests := []struct {
		freq    int
		channel int
	}{
		{2412, 1},
		{2437, 6},
		{2462, 11},
		{2472, 13},
		{2484, 14},
		{5180, 36},
		{5500, 100},
		{5825, 165},
		{1000, 0}, // unknown frequency
		{0, 0},    // zero frequency
	}
	for _, tc := range tests {
		got := freqToChannel(tc.freq)
		if got != tc.channel {
			t.Errorf("freqToChannel(%d) = %d, want %d", tc.freq, got, tc.channel)
		}
	}
}

// TestParseNilDot11 verifies Parse handles packets without a Dot11 layer.
func TestParseNilDot11(t *testing.T) {
	_, err := Parse(gopacket.NewPacket([]byte{0x00, 0x01, 0x02}, layers.LayerTypeEthernet, gopacket.Default))
	if err == nil {
		t.Error("expected error for non-Dot11 packet")
	}
}

// TestParseProbeResponse verifies probe response parsing including SSID and capability.
func TestParseProbeResponse(t *testing.T) {
	pcapData := testutil.BuildProbeRespPcap(
		testutil.SSID("ProbeNet"),
		testutil.RSSI(-50),
		testutil.Channel(11),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeProbeResponse {
		t.Errorf("expected FrameTypeProbeResponse, got %v", frame.FrameType)
	}
	if frame.SSID != "ProbeNet" {
		t.Errorf("expected SSID ProbeNet, got %q", frame.SSID)
	}
	if frame.RSSI != -50 {
		t.Errorf("expected RSSI -50, got %d", frame.RSSI)
	}
	if frame.Channel != 11 {
		t.Errorf("expected channel 11, got %d", frame.Channel)
	}
	if frame.BeaconInterval != 100 {
		t.Errorf("expected beacon interval 100, got %d", frame.BeaconInterval)
	}
}

// TestParseAssocReq verifies association request parsing.
func TestParseAssocReq(t *testing.T) {
	pcapData := testutil.BuildAssocReqPcap(
		testutil.SSID("AssocNet"),
		testutil.Channel(6),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeAssocReq {
		t.Errorf("expected FrameTypeAssocReq, got %v", frame.FrameType)
	}
	if frame.SSID != "AssocNet" {
		t.Errorf("expected SSID AssocNet, got %q", frame.SSID)
	}
}

// TestParseAssocResp verifies association response parsing.
func TestParseAssocResp(t *testing.T) {
	pcapData := testutil.BuildAssocRespPcap(
		testutil.Channel(6),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeAssocResp {
		t.Errorf("expected FrameTypeAssocResp, got %v", frame.FrameType)
	}
	if frame.Status != 0 {
		t.Errorf("expected status 0, got %d", frame.Status)
	}
}

// TestParseAction verifies action frame parsing.
func TestParseAction(t *testing.T) {
	pcapData := testutil.BuildActionPcap(testutil.Channel(1))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeAction {
		t.Errorf("expected FrameTypeAction, got %v", frame.FrameType)
	}
}

// TestParseRTS verifies RTS control frame parsing.
func TestParseRTS(t *testing.T) {
	pcapData := testutil.BuildRTSPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeRTS {
		t.Errorf("expected FrameTypeRTS, got %v", frame.FrameType)
	}
}

// TestParseCTS verifies CTS control frame parsing.
func TestParseCTS(t *testing.T) {
	pcapData := testutil.BuildCTSPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeCTS {
		t.Errorf("expected FrameTypeCTS, got %v", frame.FrameType)
	}
}

// TestParseACK verifies ACK control frame parsing.
func TestParseACK(t *testing.T) {
	pcapData := testutil.BuildACKPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeACK {
		t.Errorf("expected FrameTypeACK, got %v", frame.FrameType)
	}
}

// TestParseDataFrame verifies simple data frame parsing.
func TestParseDataFrame(t *testing.T) {
	pcapData := testutil.BuildDataPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeData {
		t.Errorf("expected FrameTypeData, got %v", frame.FrameType)
	}
}

// TestParseNullDataFrame verifies null data frame parsing.
func TestParseNullDataFrame(t *testing.T) {
	pcapData := testutil.BuildNullDataPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeNull {
		t.Errorf("expected FrameTypeNull, got %v", frame.FrameType)
	}
}

// TestParseQoSDataFrame verifies QoS data frame parsing.
func TestParseQoSDataFrame(t *testing.T) {
	pcapData := testutil.BuildQoSDataPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeQoSData {
		t.Errorf("expected FrameTypeQoSData, got %v", frame.FrameType)
	}
}

// TestParseReassocReq verifies reassociation request parsing.
func TestParseReassocReq(t *testing.T) {
	pcapData := testutil.BuildReassocReqPcap(
		testutil.SSID("ReassocNet"),
		testutil.Channel(6),
	)

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeReassocReq {
		t.Errorf("expected FrameTypeReassocReq, got %v", frame.FrameType)
	}
}

// TestParseReassocResp verifies reassociation response parsing.
func TestParseReassocResp(t *testing.T) {
	pcapData := testutil.BuildReassocRespPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeReassocResp {
		t.Errorf("expected FrameTypeReassocResp, got %v", frame.FrameType)
	}
}

// TestParseBlockAckReq verifies BlockAckReq parsing.
func TestParseBlockAckReq(t *testing.T) {
	pcapData := testutil.BuildBlockAckReqPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeBlockAckReq {
		t.Errorf("expected FrameTypeBlockAckReq, got %v", frame.FrameType)
	}
}

// TestParseBlockAck verifies BlockAck parsing.
func TestParseBlockAck(t *testing.T) {
	pcapData := testutil.BuildBlockAckPcap(testutil.Channel(6))

	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}

	if frame.FrameType != FrameTypeBlockAck {
		t.Errorf("expected FrameTypeBlockAck, got %v", frame.FrameType)
	}
}

// TestParseIEForSSID verifies raw IE SSID extraction edge cases.
func TestParseIEForSSID(t *testing.T) {
	// Empty data.
	if got, present := parseIEForSSID(nil); got != "" || present {
		t.Errorf("expected (\"\", false) for nil data, got (%q, %v)", got, present)
	}

	// Single byte (too short).
	if got, present := parseIEForSSID([]byte{0x00}); got != "" || present {
		t.Errorf("expected (\"\", false) for short data, got (%q, %v)", got, present)
	}

	// SSID IE with zero length (hidden network) — present=true, ssid="".
	if got, present := parseIEForSSID([]byte{0x00, 0x00}); got != "" || !present {
		t.Errorf("expected (\"\", true) for zero-length SSID (hidden), got (%q, %v)", got, present)
	}

	// Valid SSID IE.
	data := []byte{0x00, 0x04, 'T', 'e', 's', 't'}
	if got, present := parseIEForSSID(data); got != "Test" || !present {
		t.Errorf("expected (\"Test\", true), got (%q, %v)", got, present)
	}

	// Non-SSID IE followed by SSID IE.
	data = []byte{0x01, 0x02, 0x82, 0x84, 0x00, 0x03, 'F', 'o', 'o'}
	if got, present := parseIEForSSID(data); got != "Foo" || !present {
		t.Errorf("expected (\"Foo\", true), got (%q, %v)", got, present)
	}

	// Truncated IE (length exceeds remaining data).
	data = []byte{0x00, 0x10, 'T', 'e'}
	if got, present := parseIEForSSID(data); got != "" || present {
		t.Errorf("expected (\"\", false) for truncated IE, got (%q, %v)", got, present)
	}
}

// TestFrameTypeClassificationHelpers verifies all FrameType classification methods.
func TestFrameTypeClassificationHelpers(t *testing.T) {
	mgmtTypes := []FrameType{
		FrameTypeBeacon, FrameTypeProbeRequest, FrameTypeProbeResponse,
		FrameTypeAuth, FrameTypeDeauth, FrameTypeDisassoc,
		FrameTypeAssocReq, FrameTypeAssocResp,
		FrameTypeReassocReq, FrameTypeReassocResp, FrameTypeAction,
	}
	for _, ft := range mgmtTypes {
		if !ft.IsManagement() {
			t.Errorf("%v should be management", ft)
		}
		if ft.IsControl() {
			t.Errorf("%v should not be control", ft)
		}
		if ft.IsData() {
			t.Errorf("%v should not be data", ft)
		}
	}

	ctrlTypes := []FrameType{FrameTypeCTS, FrameTypeRTS, FrameTypeACK, FrameTypeBlockAckReq, FrameTypeBlockAck}
	for _, ft := range ctrlTypes {
		if !ft.IsControl() {
			t.Errorf("%v should be control", ft)
		}
		if ft.IsManagement() {
			t.Errorf("%v should not be management", ft)
		}
	}

	dataTypes := []FrameType{FrameTypeData, FrameTypeNull, FrameTypeQoSData}
	for _, ft := range dataTypes {
		if !ft.IsData() {
			t.Errorf("%v should be data", ft)
		}
		if ft.IsManagement() {
			t.Errorf("%v should not be management", ft)
		}
	}

	if FrameTypeUnknown.IsManagement() || FrameTypeUnknown.IsControl() || FrameTypeUnknown.IsData() {
		t.Error("Unknown type should not be management, control, or data")
	}
}

// TestFrameTypeStringAll verifies string representations for all frame types.
func TestFrameTypeStringAll(t *testing.T) {
	types := map[FrameType]string{
		FrameTypeBeacon:        "Beacon",
		FrameTypeProbeRequest:  "ProbeRequest",
		FrameTypeProbeResponse: "ProbeResponse",
		FrameTypeAuth:          "Authentication",
		FrameTypeDeauth:        "Deauthentication",
		FrameTypeDisassoc:      "Disassociation",
		FrameTypeAssocReq:      "AssociationRequest",
		FrameTypeAssocResp:     "AssociationResponse",
		FrameTypeReassocReq:    "ReassociationRequest",
		FrameTypeReassocResp:   "ReassociationResponse",
		FrameTypeAction:        "Action",
		FrameTypeCTS:           "CTS",
		FrameTypeRTS:           "RTS",
		FrameTypeACK:           "ACK",
		FrameTypeBlockAckReq:   "BlockAckReq",
		FrameTypeBlockAck:      "BlockAck",
		FrameTypeData:          "Data",
		FrameTypeNull:          "NullData",
		FrameTypeQoSData:       "QoSData",
		FrameTypeUnknown:       "Unknown",
	}
	for ft, expected := range types {
		if got := ft.String(); got != expected {
			t.Errorf("FrameType(%d).String() = %q, want %q", ft, got, expected)
		}
	}
}

// TestParseRadioTapEmpty verifies parseRadioTap handles a RadioTap header with
// no Present flags or values without panicking.
func TestParseRadioTapEmpty(t *testing.T) {
	f := &ParsedFrame{}
	rt := &layers.RadioTap{}
	parseRadioTap(f, rt) // must not panic
	if f.RSSI != 0 || f.ChannelFreq != 0 {
		t.Errorf("expected zero RSSI/ChannelFreq for empty RadioTap, got RSSI=%d ChannelFreq=%d", f.RSSI, f.ChannelFreq)
	}
}

// TestParseIEsRawCap verifies parseIEsRaw stops at maxIEsPerFrame to prevent
// unbounded memory growth from malformed frames.
func TestParseIEsRawCap(t *testing.T) {
	// Build a long sequence of zero-length IEs with unique IDs.
	// Each IE is 2 bytes (id + len), so maxIEsPerFrame*2 + extras bytes
	// represent maxIEsPerFrame+extras IEs.
	const extras = 50
	data := make([]byte, 0, (maxIEsPerFrame+extras)*2)
	for i := range maxIEsPerFrame + extras {
		data = append(data, byte(i%256), 0x00)
	}

	f := &ParsedFrame{InfoElements: make(map[uint8][]byte)}
	parseIEsRaw(data, f)

	if len(f.InfoElements) > maxIEsPerFrame {
		t.Errorf("expected at most %d IEs, got %d", maxIEsPerFrame, len(f.InfoElements))
	}
}

// TestParseIEForSSIDHidden verifies that an SSID IE with zero length is
// reported as present (hidden network), distinguishing it from a missing IE.
func TestParseIEForSSIDHidden(t *testing.T) {
	// IE: id=0 (SSID), len=0 (hidden).
	data := []byte{0x00, 0x00}
	ssid, present := parseIEForSSID(data)
	if !present {
		t.Error("expected present=true for zero-length SSID IE")
	}
	if ssid != "" {
		t.Errorf("expected empty SSID for hidden network, got %q", ssid)
	}

	// No SSID IE at all.
	dataNo := []byte{0x01, 0x01, 0xff} // some other IE
	ssid2, present2 := parseIEForSSID(dataNo)
	if present2 {
		t.Error("expected present=false when no SSID IE is in data")
	}
	if ssid2 != "" {
		t.Errorf("expected empty SSID, got %q", ssid2)
	}
}

// TestParseSSIDPresentBeacon verifies SSIDPresent is set on a parsed beacon.
func TestParseSSIDPresentBeacon(t *testing.T) {
	pcapData := testutil.BuildBeaconPcap(testutil.SSID("VisibleNet"))
	frame := parsePcapFrame(t, pcapData)
	if frame == nil {
		return
	}
	if !frame.SSIDPresent {
		t.Error("expected SSIDPresent=true for beacon with SSID IE")
	}
	if frame.SSID != "VisibleNet" {
		t.Errorf("expected SSID=VisibleNet, got %q", frame.SSID)
	}
}

// parsePcapFrame opens a pcap from bytes and parses the first frame.
func parsePcapFrame(t *testing.T, pcapData []byte) *ParsedFrame {
	t.Helper()
	frames := parsePcapFrames(t, pcapData)
	if len(frames) == 0 {
		t.Fatal("no frames parsed from pcap")
	}
	return frames[0]
}

// parsePcapFrames opens a pcap from bytes and parses all frames.
func parsePcapFrames(t *testing.T, pcapData []byte) []*ParsedFrame {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "tobimaru-test-*.pcap")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(pcapData); err != nil {
		tmpFile.Close()
		t.Fatalf("failed to write pcap data: %v", err)
	}
	tmpFile.Close()

	handle, err := pcap.OpenOffline(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open offline pcap: %v", err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, layers.LinkTypeIEEE80211Radio)
	var frames []*ParsedFrame
	for packet := range source.Packets() {
		frame, err := Parse(packet)
		if err != nil {
			t.Logf("parse error (skipping): %v", err)
			continue
		}
		frames = append(frames, frame)
	}
	return frames
}
