// Package testutil provides helpers for testing WiFi capture and parsing,
// including synthetic 802.11 frame generation and pcap file creation.
package testutil

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const dot11HeaderLen = 24

// MACAddr is a convenience type alias for MAC addresses.
type MACAddr = net.HardwareAddr

type options struct {
	srcMAC     net.HardwareAddr
	dstMAC     net.HardwareAddr
	bssid      net.HardwareAddr
	ssid       string
	channel    int
	rssi       int8
	reason     uint16
	seqNum     uint16
	floodCount int
}

// Option configures a synthetic 802.11 frame.
type Option func(*options)

// SrcMAC sets the source MAC address (Address2 in Dot11).
func SrcMAC(mac net.HardwareAddr) Option { return func(o *options) { o.srcMAC = mac } }

// DstMAC sets the destination MAC address (Address1 in Dot11).
func DstMAC(mac net.HardwareAddr) Option { return func(o *options) { o.dstMAC = mac } }

// BSSID sets the BSSID (Address3 in Dot11).
func BSSID(mac net.HardwareAddr) Option { return func(o *options) { o.bssid = mac } }

// SSID sets the SSID for beacon/probe frames.
func SSID(s string) Option { return func(o *options) { o.ssid = s } }

// Channel sets the RadioTap channel.
func Channel(ch int) Option { return func(o *options) { o.channel = ch } }

// RSSI sets the RadioTap DBMAntennaSignal field.
func RSSI(rssi int8) Option { return func(o *options) { o.rssi = rssi } }

// Reason sets the reason code for deauth/disassoc frames.
func Reason(r uint16) Option { return func(o *options) { o.reason = r } }

// SeqNum sets the sequence number.
func SeqNum(s uint16) Option { return func(o *options) { o.seqNum = s } }

// FloodCount sets the number of frames in a flood pcap (default 10).
func FloodCount(n int) Option { return func(o *options) { o.floodCount = n } }

var defaultOpts = options{
	srcMAC:     net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	dstMAC:     net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	bssid:      net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	channel:    6,
	rssi:       -45,
	reason:     1,
	floodCount: 10,
}

func captureInfo(n int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}
}

func writePcapBytes(frame []byte) []byte {
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	_ = w.WriteFileHeader(65535, layers.LinkTypeIEEE80211Radio)
	_ = w.WritePacket(captureInfo(len(frame)), frame)
	return buf.Bytes()
}

// BuildBeaconPcap creates a pcap with one beacon frame.
func BuildBeaconPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildBeaconFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildProbeReqPcap creates a pcap with one probe request frame.
func BuildProbeReqPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildProbeReqFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildDeauthPcap creates a pcap with one deauthentication frame.
func BuildDeauthPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildDeauthFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildDisassocPcap creates a pcap with one disassociation frame.
func BuildDisassocPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildDisassocFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildAuthPcap creates a pcap with one authentication frame.
func BuildAuthPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildAuthFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildMultiFramePcap creates a pcap with multiple frames of various types.
func BuildMultiFramePcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	_ = w.WriteFileHeader(65535, layers.LinkTypeIEEE80211Radio)

	frames := [][]byte{
		append(buildRadioTap(&o), buildBeaconFrame(&o)...),
		append(buildRadioTap(&o), buildProbeReqFrame(&o)...),
		append(buildRadioTap(&o), buildDeauthFrame(&o)...),
	}
	for _, f := range frames {
		_ = w.WritePacket(captureInfo(len(f)), f)
	}
	return buf.Bytes()
}

// BuildDeauthFloodPcap creates a pcap with multiple deauthentication frames
// from the same source, simulating a deauth flood attack. Frames have
// incrementing sequence numbers and timestamps spaced 1ms apart.
func BuildDeauthFloodPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	_ = w.WriteFileHeader(65535, layers.LinkTypeIEEE80211Radio)

	baseTime := time.Now()
	for i := range o.floodCount {
		o.seqNum = uint16(i)
		frame := append(buildRadioTap(&o), buildDeauthFrame(&o)...)
		t := baseTime.Add(time.Duration(i) * time.Millisecond)
		_ = w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     t,
			CaptureLength: len(frame),
			Length:        len(frame),
		}, frame)
	}
	return buf.Bytes()
}

// BuildDisassocFloodPcap creates a pcap with multiple disassociation frames
// from the same source, simulating a disassociation flood attack. Frames have
// incrementing sequence numbers and timestamps spaced 1ms apart.
func BuildDisassocFloodPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	_ = w.WriteFileHeader(65535, layers.LinkTypeIEEE80211Radio)

	baseTime := time.Now()
	for i := range o.floodCount {
		o.seqNum = uint16(i)
		frame := append(buildRadioTap(&o), buildDisassocFrame(&o)...)
		t := baseTime.Add(time.Duration(i) * time.Millisecond)
		_ = w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     t,
			CaptureLength: len(frame),
			Length:        len(frame),
		}, frame)
	}
	return buf.Bytes()
}

func applyOpts(opts ...Option) options {
	o := defaultOpts
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// ---------------------------------------------------------------------------
// RadioTap header construction
// ---------------------------------------------------------------------------

const (
	rtPresentChannel          = 1 << 3
	rtPresentDBMAntennaSignal = 1 << 5
)

func buildRadioTap(o *options) []byte {
	present := uint32(rtPresentChannel | rtPresentDBMAntennaSignal)
	length := uint16(14)

	buf := make([]byte, length)
	binary.LittleEndian.PutUint16(buf[2:4], length)
	binary.LittleEndian.PutUint32(buf[4:8], present)

	freq := channelToFreq(o.channel)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(freq))
	if freq < 5000 {
		binary.LittleEndian.PutUint16(buf[10:12], 0x00a0)
	} else {
		binary.LittleEndian.PutUint16(buf[10:12], 0x0140)
	}
	buf[12] = byte(o.rssi)

	return buf
}

// ---------------------------------------------------------------------------
// 802.11 frame builders
// ---------------------------------------------------------------------------

const (
	fcMgmt = 0x00
	fcCtrl = 0x04
	fcData = 0x08
)

const (
	fcBeacon      = 0x80
	fcProbeReq    = 0x40
	fcProbeResp   = 0x50
	fcAuth        = 0xb0
	fcDeauth      = 0xc0
	fcDisassoc    = 0xa0
	fcAssocReq    = 0x00
	fcAssocResp   = 0x10
	fcReassocReq  = 0x20
	fcReassocResp = 0x30
	fcAction      = 0xd0
)

// Data frame subtypes (main type 0x08).
const (
	fcDataSimple = 0x08 // simple data
	fcDataNull   = 0x48 // null data
	fcQoSData    = 0x88 // QoS data
)

// Control frame subtypes (main type 0x04).
const (
	fcRTS         = 0xb4
	fcCTS         = 0xc4
	fcACK         = 0xd4
	fcBlockAckReq = 0x84
	fcBlockAck    = 0x94
)

func buildDot11Header(frameControl uint16, o *options) []byte {
	buf := make([]byte, dot11HeaderLen)
	binary.LittleEndian.PutUint16(buf[0:2], frameControl)
	copy(buf[4:10], o.dstMAC)
	copy(buf[10:16], o.srcMAC)
	copy(buf[16:22], o.bssid)
	seqCtrl := (o.seqNum << 4) & 0xfff0
	binary.LittleEndian.PutUint16(buf[22:24], seqCtrl)
	return buf
}

func buildBeaconFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcBeacon, o))
	body := make([]byte, 12)
	binary.LittleEndian.PutUint16(body[8:10], 100)
	binary.LittleEndian.PutUint16(body[10:12], 0x0421)
	buf.Write(body)
	writeSSIDIE(&buf, o.ssid)
	writeSupportedRatesIE(&buf)
	return buf.Bytes()
}

func buildProbeReqFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcProbeReq, o))
	writeSSIDIE(&buf, o.ssid)
	writeSupportedRatesIE(&buf)
	return buf.Bytes()
}

func buildDeauthFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcDeauth, o))
	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body, o.reason)
	buf.Write(body)
	return buf.Bytes()
}

func buildDisassocFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcDisassoc, o))
	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body, o.reason)
	buf.Write(body)
	return buf.Bytes()
}

func buildAuthFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcAuth, o))
	body := make([]byte, 6)
	binary.LittleEndian.PutUint16(body[2:4], 1) // Seq 1
	buf.Write(body)
	return buf.Bytes()
}

func buildProbeRespFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcProbeResp, o))
	// Fixed fields: timestamp (8 bytes), beacon interval (2 bytes), capability (2 bytes).
	body := make([]byte, 12)
	binary.LittleEndian.PutUint16(body[8:10], 100)     // beacon interval
	binary.LittleEndian.PutUint16(body[10:12], 0x0421) // capability
	buf.Write(body)
	writeSSIDIE(&buf, o.ssid)
	writeSupportedRatesIE(&buf)
	return buf.Bytes()
}

func buildAssocReqFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcAssocReq, o))
	// Fixed fields: capability (2 bytes), listen interval (2 bytes).
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:2], 0x0421) // capability
	binary.LittleEndian.PutUint16(body[2:4], 10)     // listen interval
	buf.Write(body)
	writeSSIDIE(&buf, o.ssid)
	writeSupportedRatesIE(&buf)
	return buf.Bytes()
}

func buildAssocRespFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcAssocResp, o))
	// Fixed fields: capability (2 bytes), status code (2 bytes), AID (2 bytes).
	body := make([]byte, 6)
	binary.LittleEndian.PutUint16(body[0:2], 0x0421) // capability
	binary.LittleEndian.PutUint16(body[2:4], 0)      // success
	binary.LittleEndian.PutUint16(body[4:6], 1)      // AID
	buf.Write(body)
	return buf.Bytes()
}

func buildActionFrame(o *options) []byte {
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcAction, o))
	buf.WriteByte(0x00) // category: spectrum management
	buf.WriteByte(0x00) // action code
	return buf.Bytes()
}

func buildControlFrame(fc uint16, o *options) []byte {
	buf := make([]byte, dot11HeaderLen)
	binary.LittleEndian.PutUint16(buf[0:2], fc)
	copy(buf[4:10], o.dstMAC)
	copy(buf[10:16], o.srcMAC)
	return buf
}

func buildDataFrame(fc uint16, o *options) []byte {
	// QoS data frames have a 2-byte QoS control field after the standard header.
	extra := 0
	if fc == fcQoSData {
		extra = 2
	}
	buf := make([]byte, dot11HeaderLen+extra)
	binary.LittleEndian.PutUint16(buf[0:2], fc)
	copy(buf[4:10], o.dstMAC)
	copy(buf[10:16], o.srcMAC)
	copy(buf[16:22], o.bssid)
	seqCtrl := (o.seqNum << 4) & 0xfff0
	binary.LittleEndian.PutUint16(buf[22:24], seqCtrl)
	return buf
}

// BuildProbeRespPcap creates a pcap with one probe response frame.
func BuildProbeRespPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildProbeRespFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildAssocReqPcap creates a pcap with one association request frame.
func BuildAssocReqPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildAssocReqFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildAssocRespPcap creates a pcap with one association response frame.
func BuildAssocRespPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildAssocRespFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildActionPcap creates a pcap with one action frame.
func BuildActionPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildActionFrame(&o)...)
	return writePcapBytes(frame)
}

// BuildRTSPcap creates a pcap with one RTS control frame.
func BuildRTSPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildControlFrame(fcRTS, &o)...)
	return writePcapBytes(frame)
}

// BuildCTSPcap creates a pcap with one CTS control frame.
func BuildCTSPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildControlFrame(fcCTS, &o)...)
	return writePcapBytes(frame)
}

// BuildACKPcap creates a pcap with one ACK control frame.
func BuildACKPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildControlFrame(fcACK, &o)...)
	return writePcapBytes(frame)
}

// BuildDataPcap creates a pcap with one simple data frame.
func BuildDataPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildDataFrame(fcDataSimple, &o)...)
	return writePcapBytes(frame)
}

// BuildNullDataPcap creates a pcap with one null data frame.
func BuildNullDataPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildDataFrame(fcDataNull, &o)...)
	return writePcapBytes(frame)
}

// BuildQoSDataPcap creates a pcap with one QoS data frame.
func BuildQoSDataPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildDataFrame(fcQoSData, &o)...)
	return writePcapBytes(frame)
}

// BuildReassocReqPcap creates a pcap with one reassociation request frame.
func BuildReassocReqPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	var buf bytes.Buffer
	buf.Write(buildDot11Header(fcMgmt|fcReassocReq, &o))
	// Fixed fields: capability (2), listen interval (2), current AP (6).
	body := make([]byte, 10)
	binary.LittleEndian.PutUint16(body[0:2], 0x0421)
	copy(body[4:10], o.bssid)
	buf.Write(body)
	writeSSIDIE(&buf, o.ssid)
	writeSupportedRatesIE(&buf)
	frame := append(buildRadioTap(&o), buf.Bytes()...)
	return writePcapBytes(frame)
}

// BuildReassocRespPcap creates a pcap with one reassociation response frame.
func BuildReassocRespPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildAssocRespFrame(&o)...)
	// Patch frame control to reassociation response.
	// The Dot11 header starts after the RadioTap header (14 bytes).
	binary.LittleEndian.PutUint16(frame[14:16], fcMgmt|fcReassocResp)
	return writePcapBytes(frame)
}

// BuildBlockAckReqPcap creates a pcap with one BlockAckReq control frame.
func BuildBlockAckReqPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildControlFrame(fcBlockAckReq, &o)...)
	return writePcapBytes(frame)
}

// BuildBlockAckPcap creates a pcap with one BlockAck control frame.
func BuildBlockAckPcap(opts ...Option) []byte {
	o := applyOpts(opts...)
	frame := append(buildRadioTap(&o), buildControlFrame(fcBlockAck, &o)...)
	return writePcapBytes(frame)
}

// ---------------------------------------------------------------------------
// IE helpers
// ---------------------------------------------------------------------------

func writeSSIDIE(buf *bytes.Buffer, ssid string) {
	if ssid == "" {
		return
	}
	buf.WriteByte(0x00)
	buf.WriteByte(byte(len(ssid)))
	buf.WriteString(ssid)
}

func writeSupportedRatesIE(buf *bytes.Buffer) {
	rates := []byte{0x82, 0x84, 0x8b, 0x96}
	buf.WriteByte(0x01)
	buf.WriteByte(byte(len(rates)))
	buf.Write(rates)
}

func channelToFreq(ch int) int {
	if ch == 14 {
		return 2484
	}
	if ch >= 1 && ch <= 13 {
		return 2412 + (ch-1)*5
	}
	if ch >= 36 && ch <= 165 {
		return 5000 + ch*5
	}
	return 2412 + (ch-1)*5
}
