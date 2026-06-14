// Package parser provides 802.11 frame parsing, classification, and structured
// frame representation. It wraps gopacket/layers to extract relevant fields from
// RadioTap, Dot11 management, control, and data frames.
package parser

import (
	"bytes"
	"errors"
	"net"
	"time"
	"unicode/utf8"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Sentinel errors returned by Parse.
var (
	// ErrNoDot11Layer indicates the packet does not contain a Dot11 layer.
	ErrNoDot11Layer = errors.New("no Dot11 layer found in packet")
	// ErrInvalidDot11Layer indicates the Dot11 layer could not be cast.
	ErrInvalidDot11Layer = errors.New("failed to cast Dot11 layer")
	// errFrameRejected is returned when the post-classification validation
	// detects garbage fields — common on macOS where the BPF radiotap filter
	// delivers non‑802.11 noise. It is intentionally unexported so callers
	// treat it like any other parse error and drop the frame.
	errFrameRejected = errors.New("frame rejected: fields appear to be garbage")
	// errBadFCS is returned when the radiotap header's BadFCS flag is set,
	// indicating the frame failed its hardware FCS check. In RFMON mode the
	// NIC delivers all frames regardless of CRC validity — these corrupted
	// frames have valid-looking headers but garbage bodies (garbled SSIDs).
	errBadFCS = errors.New("frame rejected: bad FCS (corrupted)")
)

// beaconIntervalMax is the largest plausible beacon interval (10000 TU ≈ 10.24 s).
// Intervals beyond this range indicate garbage data misinterpreted as a beacon.
const beaconIntervalMax uint16 = 10000

// FrameType represents the high-level classification of an 802.11 frame.
type FrameType int

// Frame type constants for management, control, and data frames.
const (
	FrameTypeUnknown       FrameType = iota // unrecognized frame
	FrameTypeBeacon                         // Dot11TypeMgmtBeacon
	FrameTypeProbeRequest                   // Dot11TypeMgmtProbeReq
	FrameTypeProbeResponse                  // Dot11TypeMgmtProbeResp
	FrameTypeAuth                           // Dot11TypeMgmtAuthentication
	FrameTypeDeauth                         // Dot11TypeMgmtDeauthentication
	FrameTypeDisassoc                       // Dot11TypeMgmtDisassociation
	FrameTypeAssocReq                       // Dot11TypeMgmtAssociationReq
	FrameTypeAssocResp                      // Dot11TypeMgmtAssociationResp
	FrameTypeReassocReq                     // Dot11TypeMgmtReassociationReq
	FrameTypeReassocResp                    // Dot11TypeMgmtReassociationResp
	FrameTypeAction                         // Dot11TypeMgmtAction / ActionNoAck
	FrameTypeCTS                            // Dot11TypeCtrlCTS
	FrameTypeRTS                            // Dot11TypeCtrlRTS
	FrameTypeACK                            // Dot11TypeCtrlAck
	FrameTypeBlockAckReq                    // Dot11TypeCtrlBlockAckReq
	FrameTypeBlockAck                       // Dot11TypeCtrlBlockAck
	FrameTypeData                           // generic data frame
	FrameTypeNull                           // null data frame
	FrameTypeQoSData                        // QoS data frame
)

// frameTypeUnknownStr is the string representation of an unrecognized frame type.
const frameTypeUnknownStr = "Unknown"

// String returns a human-readable name for the frame type.
func (ft FrameType) String() string {
	switch ft {
	case FrameTypeBeacon:
		return "Beacon"
	case FrameTypeProbeRequest:
		return "ProbeRequest"
	case FrameTypeProbeResponse:
		return "ProbeResponse"
	case FrameTypeAuth:
		return "Authentication"
	case FrameTypeDeauth:
		return "Deauthentication"
	case FrameTypeDisassoc:
		return "Disassociation"
	case FrameTypeAssocReq:
		return "AssociationRequest"
	case FrameTypeAssocResp:
		return "AssociationResponse"
	case FrameTypeReassocReq:
		return "ReassociationRequest"
	case FrameTypeReassocResp:
		return "ReassociationResponse"
	case FrameTypeAction:
		return "Action"
	case FrameTypeCTS:
		return "CTS"
	case FrameTypeRTS:
		return "RTS"
	case FrameTypeACK:
		return "ACK"
	case FrameTypeBlockAckReq:
		return "BlockAckReq"
	case FrameTypeBlockAck:
		return "BlockAck"
	case FrameTypeData:
		return "Data"
	case FrameTypeNull:
		return "NullData"
	case FrameTypeQoSData:
		return "QoSData"
	default:
		return frameTypeUnknownStr
	}
}

// IsManagement returns true if the frame type is a management frame.
func (ft FrameType) IsManagement() bool {
	return ft >= FrameTypeBeacon && ft <= FrameTypeAction
}

// IsControl returns true if the frame type is a control frame.
func (ft FrameType) IsControl() bool {
	return ft >= FrameTypeCTS && ft <= FrameTypeBlockAck
}

// IsData returns true if the frame type is a data frame.
func (ft FrameType) IsData() bool {
	return ft >= FrameTypeData && ft <= FrameTypeQoSData
}

// ParsedFrame holds the extracted and structured information from an 802.11 frame.
type ParsedFrame struct {
	FrameType      FrameType        // classified frame type
	Timestamp      time.Time        // packet capture timestamp
	SrcMAC         net.HardwareAddr // source MAC (Address2 for most frames)
	DstMAC         net.HardwareAddr // destination MAC (Address1 for most frames)
	BSSID          net.HardwareAddr // BSSID (Address3 for AP frames)
	SSID           string           // SSID from beacon or probe response/request
	SSIDPresent    bool             // true when an SSID IE was observed (even if length 0 = hidden)
	Channel        int              // channel number (derived from frequency)
	ChannelFreq    int              // channel frequency in MHz (from RadioTap)
	RSSI           int              // RSSI in dBm (from RadioTap DBMAntennaSignal)
	SequenceNum    uint16           // 802.11 sequence number
	FragmentNum    uint16           // 802.11 fragment number
	ReasonCode     uint16           // reason code (deauth/disassoc)
	AuthAlgorithm  uint16           // authentication algorithm
	AuthSeq        uint16           // authentication sequence number
	AuthStatus     uint16           // authentication status code
	Status         uint16           // association status code
	InfoElements   map[uint8][]byte // parsed information elements (ID → raw data)
	Capability     uint16           // capability information field
	BeaconInterval uint16           // beacon interval (from beacon/probe resp)
	ToDS           bool             // To DS flag
	FromDS         bool             // From DS flag
	WEP            bool             // WEP flag (privacy)
	Retry          bool             // retry flag
}

// maxIEsPerFrame caps the number of information elements parsed per frame to
// prevent unbounded memory growth from malicious or malformed inputs.
const maxIEsPerFrame = 256

// Parse decodes a raw packet captured via gopacket into a ParsedFrame.
// It extracts RadioTap metadata (RSSI, channel), Dot11 addressing, and
// management/control/data-specific fields.
//
// After classification, a validation pass runs to reject frames whose
// physical-layer fields are clearly garbage. This is essential on macOS
// where the BPF radiotap filter may not correctly offset past the
// variable-length radiotap header, letting non‑802.11 noise through.
func Parse(packet gopacket.Packet) (*ParsedFrame, error) {
	f := &ParsedFrame{
		Timestamp:    packet.Metadata().Timestamp,
		InfoElements: make(map[uint8][]byte),
	}

	// Extract RadioTap layer.
	rtLayer := packet.Layer(layers.LayerTypeRadioTap)
	if rtLayer != nil {
		rt, ok := rtLayer.(*layers.RadioTap)
		if ok {
			parseRadioTap(f, rt)
			// Reject frames with bad FCS immediately. In RFMON mode the NIC
			// delivers all frames including those that failed hardware CRC —
			// their bodies are corrupted (garbled SSIDs, wrong IEs) while
			// headers may appear structurally valid.
			if hasBadFCS(rt) {
				return nil, errBadFCS
			}
		}
	}

	// Extract Dot11 layer.
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, ErrNoDot11Layer
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil, ErrInvalidDot11Layer
	}
	parseDot11(f, dot11)

	// Classify and parse subtype-specific fields.
	classifyFrame(f, dot11, packet)
	// If IEs weren't decoded by gopacket (common for probe req, assoc req),
	// parse them from the Dot11 layer payload.
	if len(f.InfoElements) == 0 && dot11Layer.LayerPayload() != nil {
		parseIEsRaw(dot11Layer.LayerPayload(), f)
	}
	// Extract SSID from manually parsed IEs if gopacket didn't decode it.
	if f.SSID == "" {
		if ssidData, ok := f.InfoElements[0]; ok {
			f.SSIDPresent = true
			f.SSID = string(ssidData)
		}
	}
	if f.Channel == 0 && f.ChannelFreq != 0 {
		f.Channel = freqToChannel(f.ChannelFreq)
	}

	// Reject frames whose physical-layer fields are clearly garbage.
	// On macOS the BPF radiotap filter often delivers non‑802.11 packets
	// whose random bytes gopacket may decode as plausible management frames
	// with garbage BSSIDs. These checks catch such false positives.
	if !validateParsedFrame(f) {
		return nil, errFrameRejected
	}

	return f, nil
}

// parseRadioTap extracts RSSI and channel information from the RadioTap header.
// It is defensive against malformed RadioTap headers where Present and
// RadioTapValues lengths may not match. Both slices must be non-empty and
// length-aligned; a mismatch indicates a corrupted or truncated header.
func parseRadioTap(f *ParsedFrame, rt *layers.RadioTap) {
	if len(rt.Present) == 0 || len(rt.RadioTapValues) == 0 || len(rt.Present) != len(rt.RadioTapValues) {
		return
	}
	if rt.Present[0].DBMAntennaSignal() {
		f.RSSI = int(rt.RadioTapValues[0].DBMAntennaSignal)
	}
	if rt.Present[0].Channel() {
		f.ChannelFreq = int(rt.RadioTapValues[0].ChannelFrequency)
	}
}

// hasBadFCS reports whether the radiotap Flags field indicates the frame
// failed its hardware FCS (Frame Check Sequence) check. In RFMON mode, the
// NIC delivers all received frames regardless of CRC validity. Frames with
// bad FCS have structurally valid headers but corrupted bodies — producing
// garbled SSIDs and bogus Information Elements.
func hasBadFCS(rt *layers.RadioTap) bool {
	if len(rt.Present) == 0 || len(rt.RadioTapValues) == 0 || len(rt.Present) != len(rt.RadioTapValues) {
		return false
	}
	if !rt.Present[0].Flags() {
		return false // Flags field not present — cannot determine FCS status
	}
	return rt.RadioTapValues[0].Flags.BadFCS()
}

// parseDot11 extracts addressing and flags from the Dot11 header.
func parseDot11(f *ParsedFrame, dot11 *layers.Dot11) {
	f.SrcMAC = dot11.Address2
	f.DstMAC = dot11.Address1
	f.BSSID = dot11.Address3
	f.SequenceNum = dot11.SequenceNumber
	f.FragmentNum = dot11.FragmentNumber
	f.ToDS = dot11.Flags.ToDS()
	f.FromDS = dot11.Flags.FromDS()
	f.WEP = dot11.Flags.WEP()
	f.Retry = dot11.Flags.Retry()
}

// classifyFrame determines the frame type and extracts subtype-specific fields.
func classifyFrame(f *ParsedFrame, dot11 *layers.Dot11, packet gopacket.Packet) {
	switch dot11.Type {
	case layers.Dot11TypeMgmtBeacon:
		f.FrameType = FrameTypeBeacon
		parseBeacon(f, packet)
	case layers.Dot11TypeMgmtProbeReq:
		f.FrameType = FrameTypeProbeRequest
		extractSSID(f, packet)
	case layers.Dot11TypeMgmtProbeResp:
		f.FrameType = FrameTypeProbeResponse
		parseProbeResp(f, packet)
	case layers.Dot11TypeMgmtAuthentication:
		f.FrameType = FrameTypeAuth
		parseAuth(f, packet)
	case layers.Dot11TypeMgmtDeauthentication:
		f.FrameType = FrameTypeDeauth
		parseDeauth(f, packet)
	case layers.Dot11TypeMgmtDisassociation:
		f.FrameType = FrameTypeDisassoc
		parseDisassoc(f, packet)
	case layers.Dot11TypeMgmtAssociationReq:
		f.FrameType = FrameTypeAssocReq
		parseAssocReq(f, packet)
	case layers.Dot11TypeMgmtAssociationResp:
		f.FrameType = FrameTypeAssocResp
		parseAssocResp(f, packet)
	case layers.Dot11TypeMgmtReassociationReq:
		f.FrameType = FrameTypeReassocReq
		parseAssocReq(f, packet)
	case layers.Dot11TypeMgmtReassociationResp:
		f.FrameType = FrameTypeReassocResp
		parseAssocResp(f, packet)
	case layers.Dot11TypeMgmtAction, layers.Dot11TypeMgmtActionNoAck:
		f.FrameType = FrameTypeAction
	case layers.Dot11TypeCtrlRTS:
		f.FrameType = FrameTypeRTS
	case layers.Dot11TypeCtrlCTS:
		f.FrameType = FrameTypeCTS
	case layers.Dot11TypeCtrlAck:
		f.FrameType = FrameTypeACK
	case layers.Dot11TypeCtrlBlockAckReq:
		f.FrameType = FrameTypeBlockAckReq
	case layers.Dot11TypeCtrlBlockAck:
		f.FrameType = FrameTypeBlockAck
	default:
		// Data frames and other types.
		mainType := dot11.Type.MainType()
		switch mainType {
		case layers.Dot11TypeCtrl:
			f.FrameType = FrameTypeUnknown
		case layers.Dot11TypeData:
			switch dot11.Type {
			case layers.Dot11TypeDataQOSData, layers.Dot11TypeDataQOSDataCFAck,
				layers.Dot11TypeDataQOSDataCFPoll, layers.Dot11TypeDataQOSDataCFAckPoll:
				f.FrameType = FrameTypeQoSData
			case layers.Dot11TypeDataNull, layers.Dot11TypeDataCFAckNoData,
				layers.Dot11TypeDataCFPollNoData, layers.Dot11TypeDataCFAckPollNoData,
				layers.Dot11TypeDataQOSNull, layers.Dot11TypeDataQOSCFPollNoData,
				layers.Dot11TypeDataQOSCFAckPollNoData:
				f.FrameType = FrameTypeNull
			default:
				f.FrameType = FrameTypeData
			}
		default:
			f.FrameType = FrameTypeUnknown
		}
	}
}

// parseBeacon extracts beacon-specific fields including IEs and SSID.
func parseBeacon(f *ParsedFrame, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); layer != nil {
		if beacon, ok := layer.(*layers.Dot11MgmtBeacon); ok {
			f.BeaconInterval = beacon.Interval
			f.Capability = beacon.Flags
		}
	}
	extractInfoElements(f, packet)
	extractSSID(f, packet)
}

// parseProbeResp extracts probe response fields.
func parseProbeResp(f *ParsedFrame, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeDot11MgmtProbeResp); layer != nil {
		if pr, ok := layer.(*layers.Dot11MgmtProbeResp); ok {
			f.BeaconInterval = pr.Interval
			f.Capability = pr.Flags
		}
	}
	extractInfoElements(f, packet)
	extractSSID(f, packet)
}

// parseAuth extracts authentication frame fields.
func parseAuth(f *ParsedFrame, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeDot11MgmtAuthentication); layer != nil {
		if auth, ok := layer.(*layers.Dot11MgmtAuthentication); ok {
			f.AuthAlgorithm = uint16(auth.Algorithm)
			f.AuthSeq = auth.Sequence
			f.AuthStatus = uint16(auth.Status)
		}
	}
}

// parseDeauth extracts deauthentication reason code.
func parseDeauth(f *ParsedFrame, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeDot11MgmtDeauthentication); layer != nil {
		if deauth, ok := layer.(*layers.Dot11MgmtDeauthentication); ok {
			f.ReasonCode = uint16(deauth.Reason)
		}
	}
}

// parseDisassoc extracts disassociation reason code.
func parseDisassoc(f *ParsedFrame, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeDot11MgmtDisassociation); layer != nil {
		if disassoc, ok := layer.(*layers.Dot11MgmtDisassociation); ok {
			f.ReasonCode = uint16(disassoc.Reason)
		}
	}
}

// parseAssocReq extracts association request fields.
func parseAssocReq(f *ParsedFrame, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeDot11MgmtAssociationReq); layer != nil {
		if areq, ok := layer.(*layers.Dot11MgmtAssociationReq); ok {
			f.Capability = areq.CapabilityInfo
		}
	}
	extractSSID(f, packet)
}

// parseAssocResp extracts association response fields.
func parseAssocResp(f *ParsedFrame, packet gopacket.Packet) {
	if layer := packet.Layer(layers.LayerTypeDot11MgmtAssociationResp); layer != nil {
		if aresp, ok := layer.(*layers.Dot11MgmtAssociationResp); ok {
			f.Status = uint16(aresp.Status)
			f.Capability = aresp.CapabilityInfo
		}
	}
}

// extractSSID extracts the SSID from IE layers or manual parsing of the
// management payload (for frame types where gopacket doesn't decode IEs).
// Sets SSIDPresent to true whenever an SSID IE (id=0) is observed, even if
// length is zero (legitimate hidden network).
func extractSSID(f *ParsedFrame, packet gopacket.Packet) {
	// Try gopacket-decoded IEs first.
	for _, l := range packet.Layers() {
		if l.LayerType() == layers.LayerTypeDot11InformationElement {
			ie, ok := l.(*layers.Dot11InformationElement)
			if ok && ie.ID == 0 {
				f.SSIDPresent = true
				if len(ie.Info) > 0 {
					f.SSID = string(ie.Info)
				}
				return
			}
		}
	}
	// Fallback: manually parse IEs from management frame payload.
	ssid, present := extractSSIDFromPayload(packet)
	if present {
		f.SSIDPresent = true
		if ssid != "" {
			f.SSID = ssid
		}
	}
}

// extractSSIDFromPayload manually parses the management frame payload for the
// SSID information element. Used when gopacket doesn't automatically decode IEs
// (e.g., for Dot11MgmtProbeReq). Returns (ssid, present) — present is true
// even for zero-length SSIDs (hidden networks).
func extractSSIDFromPayload(packet gopacket.Packet) (string, bool) {
	// Try Dot11MgmtProbeReq layer.
	if l := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); l != nil {
		return parseIEForSSID(l.LayerPayload())
	}
	// Try Dot11MgmtAssociationReq layer.
	if l := packet.Layer(layers.LayerTypeDot11MgmtAssociationReq); l != nil {
		return parseIEForSSID(l.LayerPayload())
	}
	return "", false
}

// iterateIEs walks an 802.11 information element TLV stream, calling yield
// for each (id, info) pair. Iteration stops if yield returns false, on a
// truncated record, or after maxIEsPerFrame iterations. The slice passed to
// yield aliases the input data — copy if retention is needed.
func iterateIEs(data []byte, yield func(id uint8, info []byte) bool) {
	for i := 0; len(data) >= 2 && i < maxIEsPerFrame; i++ {
		id, length := data[0], int(data[1])
		if len(data) < 2+length {
			return
		}
		if !yield(id, data[2:2+length]) {
			return
		}
		data = data[2+length:]
	}
}

// parseIEForSSID parses raw IE bytes looking for the SSID element (ID 0).
// Returns (ssid, present) — present is true even for zero-length SSIDs.
// Caps iteration at maxIEsPerFrame to defend against malformed inputs.
func parseIEForSSID(data []byte) (string, bool) {
	var ssid string
	var found bool
	iterateIEs(data, func(id uint8, info []byte) bool {
		if id == 0 {
			ssid = string(info)
			found = true
			return false // stop iteration
		}
		return true
	})
	return ssid, found
}

// extractInfoElements extracts all information elements from the packet,
// using both gopacket-decoded IEs and manual payload parsing.
func extractInfoElements(f *ParsedFrame, packet gopacket.Packet) {
	for _, l := range packet.Layers() {
		if l.LayerType() == layers.LayerTypeDot11InformationElement {
			if len(f.InfoElements) >= maxIEsPerFrame {
				break
			}
			ie, ok := l.(*layers.Dot11InformationElement)
			if ok {
				f.InfoElements[uint8(ie.ID)] = append([]byte(nil), ie.Info...)
			}
		}
	}
	// If no IEs were added via gopacket layers, try manual parsing.
	if len(f.InfoElements) == 0 {
		extractIEsFromPayload(f, packet)
	}
}

// extractIEsFromPayload manually parses IEs from management frame payloads.
func extractIEsFromPayload(f *ParsedFrame, packet gopacket.Packet) {
	if l := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); l != nil {
		parseIEsRaw(l.LayerPayload(), f)
		return
	}
	if l := packet.Layer(layers.LayerTypeDot11MgmtAssociationReq); l != nil {
		parseIEsRaw(l.LayerPayload(), f)
		return
	}
}

// parseIEsRaw parses raw IE bytes and stores them in the ParsedFrame.
// Caps the number of stored elements at maxIEsPerFrame to defend against
// malformed or malicious frames.
func parseIEsRaw(data []byte, f *ParsedFrame) {
	iterateIEs(data, func(id uint8, info []byte) bool {
		if len(f.InfoElements) >= maxIEsPerFrame {
			return false
		}
		f.InfoElements[id] = append([]byte(nil), info...)
		return true
	})
}

// freqToChannel converts a WiFi frequency (in MHz) to a channel number.
// Supports 2.4 GHz and 5 GHz bands.
func freqToChannel(freq int) int {
	if freq == 2484 {
		return 14 // 802.11b Japan only
	}
	if freq >= 2412 && freq <= 2472 {
		return (freq-2412)/5 + 1
	}
	if freq >= 5000 && freq <= 5885 {
		return (freq - 5000) / 5
	}
	return 0
}

// isUnicastMAC reports whether hw is a unicast (non-broadcast, non-multicast)
// hardware address. Valid 802.11 BSSIDs and source addresses are always unicast.
func isUnicastMAC(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}
	return hw[0]&0x01 == 0
}

// allZeroMAC reports whether hw is all zeros.
func allZeroMAC(hw net.HardwareAddr) bool {
	for _, b := range hw {
		if b != 0 {
			return false
		}
	}
	return true
}

// validateParsedFrame performs sanity checks on the fields of a parsed frame
// after classification. It returns false when the frame's physical-layer
// fields are clearly garbage — a common scenario on macOS where the BPF
// radiotap filter delivers non‑802.11 noise that gopacket may decode as
// plausible-looking management frames with random BSSIDs and intervals.
func validateParsedFrame(f *ParsedFrame) bool {
	switch f.FrameType {
	case FrameTypeBeacon:
		// 802.11 §9.3.3.2: beacons are always sent to broadcast DA
		// and Address2 (SA) == Address3 (BSSID).
		// Random bytes interpreted as a beacon header will almost
		// never satisfy both — these checks are definitive for
		// rejecting garbage/noise packets.
		if f.BSSID == nil || allZeroMAC(f.BSSID) || !isUnicastMAC(f.BSSID) {
			return false
		}
		if f.SrcMAC == nil || !bytes.Equal(f.SrcMAC, f.BSSID) {
			return false
		}
		if f.DstMAC == nil || !isBroadcastMAC(f.DstMAC) {
			return false
		}
		// Beacon interval must be non-zero and within plausible range.
		// Garbage frames typically have 0 or values >10000 TU (≈10.24s).
		if f.BeaconInterval == 0 || f.BeaconInterval > beaconIntervalMax {
			return false
		}
		// SSID must be valid: either empty (hidden network) or contain only
		// printable characters. Corrupted frames (bad FCS that slipped past
		// the radiotap check, or partial frame captures during channel hops)
		// often have intact headers but garbled bodies → garbage SSIDs.
		if f.SSID != "" && !isValidSSID(f.SSID) {
			return false
		}

	case FrameTypeProbeResponse:
		// Probe responses have SrcMAC == BSSID and are unicast to the
		// requesting client, so DstMAC can be unicast or broadcast.
		if f.BSSID == nil || allZeroMAC(f.BSSID) || !isUnicastMAC(f.BSSID) {
			return false
		}
		if f.SrcMAC == nil || !bytes.Equal(f.SrcMAC, f.BSSID) {
			return false
		}
		if f.DstMAC == nil || allZeroMAC(f.DstMAC) {
			return false
		}
		// Beacon interval must be non-zero and within plausible range.
		if f.BeaconInterval == 0 || f.BeaconInterval > beaconIntervalMax {
			return false
		}
		// SSID validation — same as beacon.
		if f.SSID != "" && !isValidSSID(f.SSID) {
			return false
		}

	case FrameTypeProbeRequest:
		// Source MAC (Address2 for probe requests) must be unicast.
		// Probe requests from broadcast or multicast addresses are garbage.
		if f.SrcMAC == nil || !isUnicastMAC(f.SrcMAC) {
			return false
		}
		// Destination is typically broadcast (wildcard probe) or a
		// specific BSSID (directed probe). All-zero is garbage.
		if f.DstMAC == nil || allZeroMAC(f.DstMAC) {
			return false
		}

	case FrameTypeAssocReq, FrameTypeReassocReq, FrameTypeAuth:
		// Source MAC must be unicast and destination must be valid.
		if f.SrcMAC == nil || !isUnicastMAC(f.SrcMAC) {
			return false
		}
		if f.DstMAC == nil || allZeroMAC(f.DstMAC) {
			return false
		}

	case FrameTypeData, FrameTypeQoSData:
		// At minimum, SrcMAC must be unicast. Garbage often has all-
		// broadcast or all-zero addresses.
		if f.SrcMAC == nil || !isUnicastMAC(f.SrcMAC) {
			return false
		}
		if f.DstMAC == nil || allZeroMAC(f.DstMAC) {
			return false
		}

	case FrameTypeUnknown, FrameTypeDeauth, FrameTypeDisassoc,
		FrameTypeAssocResp, FrameTypeReassocResp, FrameTypeAction,
		FrameTypeCTS, FrameTypeRTS, FrameTypeACK,
		FrameTypeBlockAckReq, FrameTypeBlockAck, FrameTypeNull:
		// No additional validation for these frame types.
	}

	return true
}

// isBroadcastMAC reports whether hw is the broadcast address ff:ff:ff:ff:ff:ff.
func isBroadcastMAC(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}
	for _, b := range hw {
		if b != 0xff {
			return false
		}
	}
	return true
}

// isValidSSID checks whether an SSID string contains only characters that
// a real access point would use. Valid SSIDs are:
//   - Valid UTF-8 (most real APs use ASCII or UTF-8 for multi-language SSIDs)
//   - Contain no ASCII control characters (0x00–0x1F, 0x7F)
//   - Length ≤ 32 bytes (802.11 limit)
//
// Corrupted frames from bad-FCS packets or partial captures during channel
// hops often have intact 802.11 headers but garbled frame bodies, producing
// SSIDs with non-printable bytes, invalid UTF-8 sequences, or excessive length.
func isValidSSID(ssid string) bool {
	if len(ssid) > 32 {
		return false
	}
	if !utf8.ValidString(ssid) {
		return false
	}
	for _, r := range ssid {
		if r < 0x20 || r == 0x7F {
			return false
		}
	}
	return true
}
