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
    SSIDPresent    bool             // true when an SSID IE was observed (even if length 0 = hidden)
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
  │     ├─ Channel frequency from Channel
  │     └─ BadFCS check: reject immediately if Flags.BadFCS is set
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
  ├─► Convert frequency to channel number via freqToChannel()
  │
  └─► Post-classification validation (validateParsedFrame)
        ├─ Rejects frames with garbage physical-layer fields
        ├─ Beacon: SrcMAC must equal BSSID, DstMAC must be broadcast
        ├─ ProbeResponse: SrcMAC must equal BSSID, DstMAC non-zero
        ├─ Beacon/ProbeResponse: SSID must be valid UTF-8 with no control chars
        ├─ All management: SrcMAC must be unicast, DstMAC non-zero
        └─ Returns errFrameRejected (unexported sentinel) on failure
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
- `validateParsedFrame()` runs after classification and rejects frames whose physical-layer fields are clearly garbage — essential on macOS where variable-length radiotap headers can cause BPF filters to pass non‑802.11 noise
- Beacons always have SrcMAC == BSSID and DstMAC == broadcast (ff:ff:ff:ff:ff:ff) — per 802.11 §9.3.3.2; any beacon violating this is rejected
- Probe responses always have SrcMAC == BSSID; any probe response violating this is rejected
- All management frames require a unicast SrcMAC; broadcast or multicast sources indicate garbage
- Beacon interval must be non-zero and ≤ 10000 TU (~10.24 s); garbage frames typically have 0 or implausible values
- `errFrameRejected` is unexported — callers treat it identically to any other parse error and drop the frame
- Frames with RadioTap `BadFCS` flag set are rejected before Dot11 extraction — in RFMON mode the NIC delivers all frames regardless of CRC validity; bad-FCS frames have structurally valid headers but corrupted bodies (garbled SSIDs)
- Beacon and probe response SSIDs must be valid UTF-8, contain no ASCII control characters (0x00–0x1F, 0x7F), and be ≤ 32 bytes — frames failing this check are corrupted (bad FCS that slipped past radiotap check, or partial captures during channel hops)

## Error Handling

- RadioTap `BadFCS` flag set → returns `errBadFCS` immediately (before Dot11 extraction)
- Missing Dot11 layer → returns error immediately
- Missing RadioTap layer → frame proceeds without RSSI/channel values (zero values)
- Failed subtype-specific layer cast → subtype fields remain at zero values, no error
- `validateParsedFrame()` failure → returns `errFrameRejected` (unexported sentinel, indistinguishable from other parse errors for callers)
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
