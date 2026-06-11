package parser

import (
	"bytes"
	"encoding/binary"
	"net"
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
		t.Errorf("got %v, want FrameTypeBeacon", frame.FrameType)
	}
	if frame.SSID != ssidStr {
		t.Errorf("got SSID %q, want %q", frame.SSID, ssidStr)
	}
	if frame.RSSI != -42 {
		t.Errorf("got RSSI %d, want -42", frame.RSSI)
	}
	if frame.Channel != 6 {
		t.Errorf("got channel %d, want 6", frame.Channel)
	}
	if frame.SequenceNum != 100 {
		t.Errorf("got sequence %d, want 100", frame.SequenceNum)
	}
	if len(frame.SrcMAC) != 6 {
		t.Errorf("got source MAC %v, want 6-byte MAC", frame.SrcMAC)
	}
	if len(frame.BSSID) != 6 {
		t.Errorf("got BSSID %v, want 6-byte MAC", frame.BSSID)
	}
	if frame.BeaconInterval != 100 {
		t.Errorf("got beacon interval %d, want 100", frame.BeaconInterval)
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
		t.Errorf("got %v, want FrameTypeProbeRequest", frame.FrameType)
	}
	if frame.SSID != "MyWiFi" {
		t.Errorf("got SSID %q, want MyWiFi", frame.SSID)
	}
	if frame.RSSI != -55 {
		t.Errorf("got RSSI %d, want -55", frame.RSSI)
	}
	if frame.Channel != 1 {
		t.Errorf("got channel %d, want 1", frame.Channel)
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
		t.Errorf("got %v, want FrameTypeDeauth", frame.FrameType)
	}
	if frame.ReasonCode != 7 {
		t.Errorf("got reason code %d, want 7", frame.ReasonCode)
	}
	if frame.RSSI != -60 {
		t.Errorf("got RSSI %d, want -60", frame.RSSI)
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
		t.Errorf("got %v, want FrameTypeDisassoc", frame.FrameType)
	}
	if frame.ReasonCode != 3 {
		t.Errorf("got reason code %d, want 3", frame.ReasonCode)
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
		t.Errorf("got %v, want FrameTypeAuth", frame.FrameType)
	}
	if frame.AuthSeq != 1 {
		t.Errorf("got auth seq %d, want 1", frame.AuthSeq)
	}
}

// TestParseMultiFrame verifies parsing multiple frames from a single pcap.
func TestParseMultiFrame(t *testing.T) {
	pcapData := testutil.BuildMultiFramePcap(
		testutil.SSID("MultiSSID"),
	)

	frames := parsePcapFrames(t, pcapData)
	if len(frames) < 3 {
		t.Fatalf("got %d frames, want at least 3", len(frames))
	}

	expected := []FrameType{FrameTypeBeacon, FrameTypeProbeRequest, FrameTypeDeauth}
	for i, ft := range expected {
		if i >= len(frames) {
			break
		}
		if frames[i].FrameType != ft {
			t.Errorf("frame %d: got %v, want %v", i, frames[i].FrameType, ft)
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
		t.Errorf("got %v, want FrameTypeProbeResponse", frame.FrameType)
	}
	if frame.SSID != "ProbeNet" {
		t.Errorf("got SSID %q, want ProbeNet", frame.SSID)
	}
	if frame.RSSI != -50 {
		t.Errorf("got RSSI %d, want -50", frame.RSSI)
	}
	if frame.Channel != 11 {
		t.Errorf("got channel %d, want 11", frame.Channel)
	}
	if frame.BeaconInterval != 100 {
		t.Errorf("got beacon interval %d, want 100", frame.BeaconInterval)
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
		t.Errorf("got %v, want FrameTypeAssocReq", frame.FrameType)
	}
	if frame.SSID != "AssocNet" {
		t.Errorf("got SSID %q, want AssocNet", frame.SSID)
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
		t.Errorf("got %v, want FrameTypeAssocResp", frame.FrameType)
	}
	if frame.Status != 0 {
		t.Errorf("got status %d, want 0", frame.Status)
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
		t.Errorf("got %v, want FrameTypeAction", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeRTS", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeCTS", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeACK", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeData", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeNull", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeQoSData", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeReassocReq", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeReassocResp", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeBlockAckReq", frame.FrameType)
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
		t.Errorf("got %v, want FrameTypeBlockAck", frame.FrameType)
	}
}

// TestParseIEForSSID verifies raw IE SSID extraction edge cases.
func TestParseIEForSSID(t *testing.T) {
	// Empty data.
	if got, present := parseIEForSSID(nil); got != "" || present {
		t.Errorf("got (%q, %v) for nil data, want (\"\", false)", got, present)
	}

	// Single byte (too short).
	if got, present := parseIEForSSID([]byte{0x00}); got != "" || present {
		t.Errorf("got (%q, %v) for short data, want (\"\", false)", got, present)
	}

	// SSID IE with zero length (hidden network) — present=true, ssid="".
	if got, present := parseIEForSSID([]byte{0x00, 0x00}); got != "" || !present {
		t.Errorf("got (%q, %v) for zero-length SSID (hidden), want (\"\", true)", got, present)
	}

	// Valid SSID IE.
	data := []byte{0x00, 0x04, 'T', 'e', 's', 't'}
	if got, present := parseIEForSSID(data); got != "Test" || !present {
		t.Errorf("got (%q, %v), want (\"Test\", true)", got, present)
	}

	// Non-SSID IE followed by SSID IE.
	data = []byte{0x01, 0x02, 0x82, 0x84, 0x00, 0x03, 'F', 'o', 'o'}
	if got, present := parseIEForSSID(data); got != "Foo" || !present {
		t.Errorf("got (%q, %v), want (\"Foo\", true)", got, present)
	}

	// Truncated IE (length exceeds remaining data).
	data = []byte{0x00, 0x10, 'T', 'e'}
	if got, present := parseIEForSSID(data); got != "" || present {
		t.Errorf("got (%q, %v) for truncated IE, want (\"\", false)", got, present)
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

// TestHasBadFCS verifies the bad FCS detection logic on RadioTap headers.
func TestHasBadFCS(t *testing.T) {
	// Empty RadioTap.
	if hasBadFCS(&layers.RadioTap{}) {
		t.Error("empty RadioTap should not have bad FCS")
	}

	// Present and Values lengths mismatch (defensive).
	if hasBadFCS(&layers.RadioTap{
		Present:        []layers.RadioTapPresent{0},
		RadioTapValues: []layers.RadioTapNamespace{},
	}) {
		t.Error("mismatched lengths should return false")
	}

	// Flags not present in Present[0].
	if hasBadFCS(&layers.RadioTap{
		Present:        []layers.RadioTapPresent{1}, // TSFT present, not Flags
		RadioTapValues: []layers.RadioTapNamespace{{}},
	}) {
		t.Error("no Flags present should return false")
	}

	// Flags present but BadFCS not set.
	if hasBadFCS(&layers.RadioTap{
		Present:        []layers.RadioTapPresent{2}, // Flags present (bit 1)
		RadioTapValues: []layers.RadioTapNamespace{{}},
	}) {
		t.Error("Flags present but BadFCS not set should return false")
	}

	// Flags present and BadFCS set.
	if !hasBadFCS(&layers.RadioTap{
		Present: []layers.RadioTapPresent{2},
		RadioTapValues: []layers.RadioTapNamespace{{
			Flags: layers.RadioTapFlagsBadFCS,
		}},
	}) {
		t.Error("BadFCS set should return true")
	}
}

// TestParseRadioTapEmpty verifies parseRadioTap handles a RadioTap header with
// no Present flags or values without panicking.
func TestParseRadioTapEmpty(t *testing.T) {
	f := &ParsedFrame{}
	rt := &layers.RadioTap{}
	parseRadioTap(f, rt) // must not panic
	if f.RSSI != 0 || f.ChannelFreq != 0 {
		t.Errorf("got RSSI=%d ChannelFreq=%d for empty RadioTap, want zero", f.RSSI, f.ChannelFreq)
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
		t.Errorf("got %d IEs, want at most %d", len(f.InfoElements), maxIEsPerFrame)
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
		t.Errorf("got SSID %q for hidden network, want empty", ssid)
	}

	// No SSID IE at all.
	dataNo := []byte{0x01, 0x01, 0xff} // some other IE
	ssid2, present2 := parseIEForSSID(dataNo)
	if present2 {
		t.Error("expected present=false when no SSID IE is in data")
	}
	if ssid2 != "" {
		t.Errorf("got SSID %q, want empty", ssid2)
	}
}

// buildAssocReqPacket creates a gopacket.Packet containing a Radiotap +
// Dot11 + Dot11MgmtAssociationReq with the given payload bytes.
func buildAssocReqPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()

	var buf bytes.Buffer
	// Radiotap header (8 bytes, no fields).
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0))  // version
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0))  // pad
	_ = binary.Write(&buf, binary.LittleEndian, uint16(8)) // length
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // present (no fields)

	// Dot11 header (24 bytes): AssocReq (type=Mgmt, subtype=AssocReq=0x00).
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0000)) // FrameControl: Mgmt|AssocReq
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))      // Duration
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})       // Address1 (DA)
	buf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})       // Address2 (SA)
	buf.Write([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})       // Address3 (BSSID)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))      // SequenceControl

	// Dot11MgmtAssociationReq body (4 bytes): CapabilityInfo + ListenInterval.
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0001)) // Capability (ESS)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(10))     // ListenInterval

	// Payload (IE bytes).
	buf.Write(payload)

	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeIEEE80211Radio, gopacket.Default)
}

// buildProbeReqPacket creates a gopacket.Packet containing a Radiotap +
// Dot11 + Dot11MgmtProbeReq with the given payload bytes.
func buildProbeReqPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()

	var buf bytes.Buffer
	// Radiotap header (8 bytes, no fields).
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0))  // version
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0))  // pad
	_ = binary.Write(&buf, binary.LittleEndian, uint16(8)) // length
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // present

	// Dot11 header (24 bytes): ProbeReq (type=Mgmt, subtype=ProbeReq=0x04).
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0040)) // FrameControl: Mgmt|ProbeReq
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))      // Duration
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})       // Address1 (DA)
	buf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})       // Address2 (SA)
	buf.Write([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})       // Address3 (BSSID)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))      // SequenceControl

	// Payload (IE bytes, ProbeReq has no own body fields).
	buf.Write(payload)

	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeIEEE80211Radio, gopacket.Default)
}

// TestExtractSSIDFromPayload verifies SSID extraction from both ProbeReq
// and AssociationReq management frame payloads.
func TestExtractSSIDFromPayload(t *testing.T) {
	// AssocReq with SSID IE (Dot11MgmtAssociationReq.DecodeFromBytes sets
	// Payload to the IE bytes after Capability+ListenInterval).
	payload := []byte{0x00, 0x04, 'T', 'e', 's', 't'} // id=0(SSID), len=4, "Test"
	pkt := buildAssocReqPacket(t, payload)
	ssid, present := extractSSIDFromPayload(pkt)
	if !present {
		t.Error("expected SSID to be present in AssocReq")
	}
	if ssid != "Test" {
		t.Errorf("got SSID %q, want %q", ssid, "Test")
	}

	// ProbeReq path: Dot11MgmtProbeReq.DecodeFromBytes does NOT set Payload,
	// so LayerPayload() returns nil. The real SSID extraction for ProbeReq
	// happens via dot11.LayerPayload() in Parse(). extractSSIDFromPayload
	// is reached but returns ("", false) for ProbeReq.
	pkt2 := buildProbeReqPacket(t, payload)
	ssid2, present2 := extractSSIDFromPayload(pkt2)
	if present2 {
		t.Error("expected SSID not present via extractSSIDFromPayload for ProbeReq (LayerPayload is nil)")
	}
	if ssid2 != "" {
		t.Errorf("got SSID %q, want empty", ssid2)
	}

	// Packet without management layers (should return "", false).
	emptyPkt := gopacket.NewPacket([]byte{0x00}, layers.LinkTypeEthernet, gopacket.Default)
	ssid3, present3 := extractSSIDFromPayload(emptyPkt)
	if present3 {
		t.Error("expected SSID not present for non-mgmt packet")
	}
	if ssid3 != "" {
		t.Errorf("got SSID %q, want empty", ssid3)
	}
}

// TestExtractIEsFromPayload verifies information element extraction from
// management frame payloads via the extractIEsFromPayload function.
func TestExtractIEsFromPayload(t *testing.T) {
	// Build IE bytes: SSID(id=0,len=4,"WiFi") + SupportedRates(id=1,len=2,{0x82,0x84}).
	payload := []byte{
		0x00, 0x04, 'W', 'i', 'F', 'i',
		0x01, 0x02, 0x82, 0x84,
	}

	// AssocReq path.
	pkt := buildAssocReqPacket(t, payload)
	f := &ParsedFrame{InfoElements: make(map[uint8][]byte)}
	extractIEsFromPayload(f, pkt)
	if len(f.InfoElements) != 2 {
		t.Errorf("got %d IEs from AssocReq, want 2", len(f.InfoElements))
	}
	if string(f.InfoElements[0]) != "WiFi" {
		t.Errorf("got SSID IE %q, want %q", f.InfoElements[0], "WiFi")
	}
	if len(f.InfoElements[1]) != 2 || f.InfoElements[1][0] != 0x82 {
		t.Errorf("got SupportedRates IE %v, want [0x82 0x84]", f.InfoElements[1])
	}

	// ProbeReq path: Dot11MgmtProbeReq.DecodeFromBytes does NOT set Payload,
	// so no IEs are extracted via this path. The real IE extraction happens
	// via dot11.LayerPayload() in Parse().
	pkt2 := buildProbeReqPacket(t, payload)
	f2 := &ParsedFrame{InfoElements: make(map[uint8][]byte)}
	extractIEsFromPayload(f2, pkt2)
	if len(f2.InfoElements) != 0 {
		t.Errorf("got %d IEs from ProbeReq, want 0 (LayerPayload is nil)", len(f2.InfoElements))
	}

	// Packet without management layers should be a no-op.
	f3 := &ParsedFrame{InfoElements: make(map[uint8][]byte)}
	emptyPkt := gopacket.NewPacket([]byte{0x00}, layers.LinkTypeEthernet, gopacket.Default)
	extractIEsFromPayload(f3, emptyPkt)
	if len(f3.InfoElements) != 0 {
		t.Errorf("got %d IEs from non-mgmt packet, want 0", len(f3.InfoElements))
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
		t.Errorf("got SSID %q, want VisibleNet", frame.SSID)
	}
}

// TestIsUnicastMAC verifies unicast MAC address detection.
func TestIsUnicastMAC(t *testing.T) {
	// Valid unicast — LSb of first octet is 0.
	if !isUnicastMAC(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Error("expected unicast")
	}
	// Multicast — LSb of first octet is 1.
	if isUnicastMAC(net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}) {
		t.Error("expected not unicast (multicast)")
	}
	// Broadcast.
	if isUnicastMAC(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Error("expected not unicast (broadcast)")
	}
	// Nil.
	if isUnicastMAC(nil) {
		t.Error("expected not unicast (nil)")
	}
	// Wrong length.
	if isUnicastMAC(net.HardwareAddr{0x00, 0x11, 0x22}) {
		t.Error("expected not unicast (wrong length)")
	}
}

// TestAllZeroMAC verifies all-zero MAC detection.
func TestAllZeroMAC(t *testing.T) {
	if !allZeroMAC(net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		t.Error("expected all-zero to be detected")
	}
	if allZeroMAC(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Error("expected not all-zero")
	}
	// Nil/empty — no bytes, so no non-zero bytes; treated as all-zero.
	if !allZeroMAC(nil) {
		t.Error("expected nil to be all-zero")
	}
	if !allZeroMAC(net.HardwareAddr{}) {
		t.Error("expected empty to be all-zero")
	}
	// Partially zero.
	if allZeroMAC(net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}) {
		t.Error("expected not all-zero when last byte is non-zero")
	}
}

// TestIsBroadcastMAC verifies broadcast MAC detection.
func TestIsBroadcastMAC(t *testing.T) {
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if !isBroadcastMAC(bcast) {
		t.Error("expected broadcast")
	}
	if isBroadcastMAC(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}) {
		t.Error("expected not broadcast (last byte differs)")
	}
	if isBroadcastMAC(nil) {
		t.Error("expected nil to not be broadcast")
	}
	if isBroadcastMAC(net.HardwareAddr{0xff, 0xff, 0xff}) {
		t.Error("expected wrong length to not be broadcast")
	}
}

// TestIsValidSSID verifies SSID validation rules.
func TestIsValidSSID(t *testing.T) {
	if !isValidSSID("MyWiFi") {
		t.Error("expected valid SSID")
	}
	if !isValidSSID("") {
		t.Error("expected empty SSID to be valid")
	}
	// Too long (>32 bytes).
	if isValidSSID("abcdefghijklmnopqrstuvwxyz1234567") { // 33 chars
		t.Error("expected too-long SSID to be invalid")
	}
	// Control character.
	if isValidSSID("bad\x01ssid") {
		t.Error("expected SSID with control char to be invalid")
	}
	// DEL character (0x7F).
	if isValidSSID("bad\x7fssid") {
		t.Error("expected SSID with DEL char to be invalid")
	}
	// Valid UTF-8 multi-byte SSID.
	if !isValidSSID("café-ネット") {
		t.Error("expected UTF-8 SSID to be valid")
	}
}

// TestValidateParsedFrame covers additional validation paths.
func TestValidateParsedFrame(t *testing.T) {
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	bcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	// Beacon: SrcMAC != BSSID → reject.
	f := &ParsedFrame{FrameType: FrameTypeBeacon, BSSID: mac2, SrcMAC: mac1, DstMAC: bcast, BeaconInterval: 100}
	if validateParsedFrame(f) {
		t.Error("beacon with mismatched SrcMAC/BSSID should be rejected")
	}

	// Beacon: beacon interval 0 → reject.
	f = &ParsedFrame{FrameType: FrameTypeBeacon, BSSID: mac2, SrcMAC: mac2, DstMAC: bcast, BeaconInterval: 0}
	if validateParsedFrame(f) {
		t.Error("beacon with zero interval should be rejected")
	}

	// Beacon: non-broadcast DstMAC → reject.
	f = &ParsedFrame{FrameType: FrameTypeBeacon, BSSID: mac2, SrcMAC: mac2, DstMAC: mac1, BeaconInterval: 100}
	if validateParsedFrame(f) {
		t.Error("beacon with non-broadcast DstMAC should be rejected")
	}

	// AssocReq: nil SrcMAC → reject.
	f = &ParsedFrame{FrameType: FrameTypeAssocReq, SrcMAC: nil, DstMAC: mac2}
	if validateParsedFrame(f) {
		t.Error("assoc req with nil SrcMAC should be rejected")
	}

	// AssocReq: all-zero DstMAC → reject.
	zeroMAC, _ := net.ParseMAC("00:00:00:00:00:00")
	f = &ParsedFrame{FrameType: FrameTypeAssocReq, SrcMAC: mac1, DstMAC: zeroMAC}
	if validateParsedFrame(f) {
		t.Error("assoc req with all-zero DstMAC should be rejected")
	}

	// Auth: valid frame.
	f = &ParsedFrame{FrameType: FrameTypeAuth, SrcMAC: mac1, DstMAC: mac2}
	if !validateParsedFrame(f) {
		t.Error("valid auth frame should pass")
	}

	// ReassocReq: valid frame.
	f = &ParsedFrame{FrameType: FrameTypeReassocReq, SrcMAC: mac1, DstMAC: mac2}
	if !validateParsedFrame(f) {
		t.Error("valid reassoc req frame should pass")
	}

	// Data: nil SrcMAC → reject.
	f = &ParsedFrame{FrameType: FrameTypeData, SrcMAC: nil, DstMAC: mac2}
	if validateParsedFrame(f) {
		t.Error("data frame with nil SrcMAC should be rejected")
	}

	// QoSData: all-zero DstMAC → reject.
	f = &ParsedFrame{FrameType: FrameTypeQoSData, SrcMAC: mac1, DstMAC: zeroMAC}
	if validateParsedFrame(f) {
		t.Error("qos data with all-zero DstMAC should be rejected")
	}

	// Unknown frame type should pass.
	f = &ParsedFrame{FrameType: FrameTypeUnknown}
	if !validateParsedFrame(f) {
		t.Error("unknown frame type should pass validation")
	}

	// Deauth should pass (no additional validation).
	f = &ParsedFrame{FrameType: FrameTypeDeauth}
	if !validateParsedFrame(f) {
		t.Error("deauth should pass validation")
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
