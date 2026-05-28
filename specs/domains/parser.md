# 802.11 Frame Parser

## Purpose

Parses raw captured 802.11 frames with RadioTap headers into structured `ParsedFrame` objects. Provides frame classification (17 management/control/data types), Information Element extraction, and frequency-to-channel conversion.

## Key Files

- `internal/parser/parser.go` — `ParsedFrame` struct, `FrameType` enum, `Parse()` function, all parsing helpers
- `internal/parser/parser_test.go` — tests for beacon, probe, deauth, disassoc, auth, multi-frame parsing, frame type classification

## Core Types

```go
type FrameType int

const (
    FrameTypeUnknown       FrameType = iota
    FrameTypeBeacon
    FrameTypeProbeRequest
    FrameTypeProbeResponse
    FrameTypeAuth
    FrameTypeDeauth
    FrameTypeDisassoc
    FrameTypeAssocReq
    FrameTypeAssocResp
    FrameTypeReassocReq
    FrameTypeReassocResp
    FrameTypeAction
    FrameTypeCTS
    FrameTypeRTS
    FrameTypeACK
    FrameTypeBlockAckReq
    FrameTypeBlockAck
    FrameTypeData
    FrameTypeNull
    FrameTypeQoSData
)
```

`FrameType` provides classification helpers: `IsManagement()`, `IsControl()`, `IsData()`, and `String()` for human-readable display.

```go
type ParsedFrame struct {
    FrameType      FrameType
    Timestamp      time.Time
    SrcMAC         net.HardwareAddr
    DstMAC         net.HardwareAddr
    BSSID          net.HardwareAddr
    SSID           string
    Channel        int
    ChannelFreq    int
    RSSI           int
    SequenceNum    uint16
    FragmentNum    uint16
    ReasonCode     uint16
    AuthAlgorithm  uint16
    AuthSeq        uint16
    AuthStatus     uint16
    Status         uint16
    InfoElements   map[uint8][]byte
    Capability     uint16
    BeaconInterval uint16
    ToDS           bool
    FromDS         bool
    WEP            bool
    Retry          bool
}
```

**Key function:**
```go
func Parse(packet gopacket.Packet) (*ParsedFrame, error)
```

## Flow

```
Parse(packet)
  │
  ├─► Extract RadioTap layer
  │     ├─ RSSI from DBMAntennaSignal
  │     └─ Channel frequency from Channel
  │
  ├─► Extract Dot11 layer (required)
  │     ├─ Source, destination, BSSID MACs
  │     ├─ Sequence and fragment numbers
  │     └─ Flags: ToDS, FromDS, WEP, Retry
  │
  ├─► Classify frame via switch on dot11.Type
  │     ├─ Management types: beacon, probe req/resp, auth, deauth,
  │     │   disassoc, assoc req/resp, reassoc req/resp, action
  │     ├─ Control types: RTS, CTS, ACK, BlockAckReq, BlockAck
  │     └─ Data types: generic, QoS, null
  │
  ├─► Extract subtype-specific fields
  │     ├─ Beacon/probe resp: interval, capability, IEs, SSID
  │     ├─ Auth: algorithm, sequence, status
  │     ├─ Deauth/disassoc: reason code
  │     └─ Assoc req/resp: capability, status, SSID
  │
  ├─► Fallback IE parsing from Dot11 layer payload
  │     └─ For probe/assoc frames where gopacket doesn't decode IEs
  │
  └─► Convert frequency to channel number via freqToChannel()
```

## Invariants

- `Parse()` always populates addressing fields (SrcMAC, DstMAC, BSSID) from Dot11 header
- The Dot11 layer is mandatory — `Parse()` returns an error if it is absent
- Frame classification uses a switch on `dot11.Type` for all known management and control types
- Data frames are classified by `dot11.Type.MainType()` with sub-classification for QoSData and Null variants
- Unknown frames are assigned `FrameTypeUnknown` — the pipeline discards them
- Information Elements are extracted from gopacket-decoded layers first, then fall back to manual parsing from Dot11 layer payload for probe request and association request frames (where gopacket does not automatically decode IEs)
- SSID is extracted: gopacket IE layers first, then manual payload parsing if not found
- Channel is derived from frequency if not directly reported in RadioTap

## Error Handling

- Missing Dot11 layer → returns error immediately
- Missing RadioTap layer → frame proceeds without RSSI/channel values (zero values)
- Failed subtype-specific layer cast → subtype fields remain at zero values, no error
- IE parsing always succeeds (robust to malformed payloads with bounds checking)

## Configuration

No direct configuration — entirely driven by input packets.

## Extension Points

- **Adding a new frame subtype:** add a `FrameType` constant, add a case in `classifyFrame()`, add subtype-specific parsing if needed, add a `String()` case
- **Adding a new extracted field:** add field to `ParsedFrame`, populate in the relevant `parse*()` function
- **Supporting new IE types:** already handled generically via the `InfoElements` map (uint8 ID → raw data)

## Related Specs

- [Capture Pipeline](capture.md) — consumes `ParsedFrame` in the capture pipeline
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — `ParsedFrame` flows through `Pipeline.Frames()` channel
