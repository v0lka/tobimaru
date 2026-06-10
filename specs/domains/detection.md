# Detection Engine

## Purpose

Provides WiFi intrusion detection by aggregating detection rules, dispatching parsed 802.11 frames to all registered rules, deduplicating security events, and emitting alerts on a channel. Rules are pure functions that analyze frames and return security events when attack patterns are detected.

## Key Files

- `internal/detector/detector.go` — `Engine` aggregator, dispatch goroutine, deduplication logic
- `internal/detector/rule.go` — `Rule` interface definition
- `internal/detector/event.go` — `SecurityEvent` struct, `Severity` enum
- `internal/detector/rule_flood.go` — shared `floodRule` helper for deauth/disassoc flood rules
- `internal/detector/rule_helpers.go` — utility functions (MAC normalization, broadcast check, etc.)
- `internal/detector/rule_beacon_flood.go` — `BeaconFloodRule` implementation
- `internal/detector/rule_deauth_flood.go` — `DeauthFloodRule` implementation (delegates to `floodRule`)
- `internal/detector/rule_disassoc_flood.go` — `DisassocFloodRule` implementation (delegates to `floodRule`)
- `internal/detector/rule_evil_twin.go` — `EvilTwinRule` implementation
- `internal/detector/rule_unauthorized_device.go` — `UnauthorizedDeviceRule` implementation
- `internal/detector/detector_test.go` — tests for engine dispatch, dedup, lifecycle, shutdown
- `internal/detector/event_test.go` — tests for severity ordering, event construction
- `internal/detector/rule_test.go` — tests for rule interface compliance
- `internal/detector/rule_beacon_flood_test.go`, `rule_deauth_flood_test.go`, `rule_disassoc_flood_test.go`, `rule_evil_twin_test.go`, `rule_unauthorized_device_test.go` — per-rule unit tests
- `internal/detector/rule_pcap_integration_test.go` — pcap-based integration tests
- `internal/config/config.go` — `DetectionConfig` struct (engine-level configuration)
- `internal/config/defaults.go` — detection defaults (dedup_window=30s, alert_buffer_size=256, rule-specific defaults)

## Core Types

### SecurityEvent

```go
type Severity int

const (
    SeverityInfo     Severity = iota // informational, no immediate threat
    SeverityWarning                  // potential threat, needs attention
    SeverityCritical                 // active attack, immediate action recommended
)

type SecurityEvent struct {
    Timestamp   time.Time          // detection time
    EventType   string             // attack type identifier (e.g., "deauth_flood")
    Severity    Severity           // info/warning/critical
    SrcMAC      net.HardwareAddr   // attacking device MAC
    DstMAC      net.HardwareAddr   // victim/client MAC
    BSSID       net.HardwareAddr   // targeted/spoofed AP BSSID
    SSID        string             // associated SSID
    Channel     int                // observed channel
    RSSI        int                // signal strength (dBm)
    FrameCount  int                // frames observed in detection window
    Duration    time.Duration      // attack duration
    Metadata    map[string]any     // rule-specific metadata
    Description string             // human-readable summary
}

func NewEvent(timestamp time.Time, eventType string, severity Severity) *SecurityEvent
```

`NewEvent()` initializes the `Metadata` map to an empty map. `String()` produces a human-readable summary.

### Rule Interface

```go
type Rule interface {
    Name() string
    Init(cfg config.DetectionConfig) error
    Process(frame *parser.ParsedFrame) []*SecurityEvent
}
```

- `Name()` — unique human-readable identifier, e.g. "deauth_flood", "evil_twin"
- `Init(cfg)` — called once at registration; extracts rule-specific parameters from config
- `Process(frame)` — evaluates a parsed frame; returns zero or more security events. Must not retain the frame pointer after returning. Must not block or panic.

### DetectionEngine

```go
type Engine struct { /* ... */ }

func NewEngine(cfg config.DetectionConfig) *Engine
func (e *Engine) Register(rule Rule) error
func (e *Engine) RuleCount() int
func (e *Engine) Run(ctx context.Context, frames <-chan *parser.ParsedFrame)
func (e *Engine) Alerts() <-chan *SecurityEvent
```

- `NewEngine(cfg)` — creates engine with buffered alerts channel and dedup map
- `Register(rule)` — validates rule name uniqueness and calls `rule.Init(cfg)`; returns error on duplicate name or init failure
- `RuleCount()` — returns the number of registered detection rules
- `Run(ctx, frames)` — starts dispatch goroutine (reading frames, dispatching to rules, deduplicating, emitting alerts). Returns immediately. Goroutine exits on ctx cancellation or frames channel close.
- `Alerts()` — returns read-only alerts channel; closes when dispatch goroutine exits

### DetectionConfig

```go
type DetectionConfig struct {
    Enabled         bool          `yaml:"enabled"`
    DedupWindow     time.Duration `yaml:"dedup_window"`
    AlertBufferSize int           `yaml:"alert_buffer_size"`

    DeauthFlood        DeauthFloodConfig        `yaml:"deauth_flood"`
    DisassocFlood      DisassocFloodConfig      `yaml:"disassoc_flood"`
    BeaconFlood        BeaconFloodConfig        `yaml:"beacon_flood"`
    EvilTwin           EvilTwinConfig           `yaml:"evil_twin"`
    UnauthorizedDevice UnauthorizedDeviceConfig `yaml:"unauthorized_device"`
}

type DeauthFloodConfig struct {
    Enabled   bool          `yaml:"enabled"`
    Threshold int           `yaml:"threshold"` // default: 10
    Window    time.Duration `yaml:"window"`    // default: 10s
}

type DisassocFloodConfig struct {
    Enabled   bool          `yaml:"enabled"`
    Threshold int           `yaml:"threshold"` // default: 10
    Window    time.Duration `yaml:"window"`    // default: 10s
}

type BeaconFloodConfig struct {
    Enabled        bool          `yaml:"enabled"`
    Threshold      int           `yaml:"threshold"`       // default: 50
    Window         time.Duration `yaml:"window"`          // default: 10s
    LearningPeriod time.Duration `yaml:"learning_period"` // default: 60s
}

type EvilTwinConfig struct {
    Enabled        bool          `yaml:"enabled"`
    ScoreThreshold int           `yaml:"score_threshold"` // default: 80
    StaleTimeout   time.Duration `yaml:"stale_timeout"`   // default: 5m
    LearningPeriod time.Duration `yaml:"learning_period"` // default: 60s
    MinBeacons     int           `yaml:"min_beacons"`     // default: 3
}

type UnauthorizedDeviceConfig struct {
    Enabled         bool          `yaml:"enabled"`
    ProtectedBSSIDs []string      `yaml:"protected_bssids"`
    ProtectedSSIDs  []string      `yaml:"protected_ssids"`
    Whitelist       []string      `yaml:"whitelist"`
    AlertOnProbe    bool          `yaml:"alert_on_probe"`
    Cooldown        time.Duration `yaml:"cooldown"`        // default: 5m
}
```

## Flow

### Dispatch Loop

```
Run(ctx, frames)
  │
  └─► goroutine:
        ├─ select { ctx.Done(), ticker, frames }
        │
        ├─ On frame:
        │   ├─ dispatch(frame) → for each rule: processRule(rule, frame)
        │   │   ├─ Rule.Process(frame) → []*SecurityEvent
        │   │   └─ For each event: emit(event)
        │   │       ├─ Compute dedup key: eventType:srcMAC:bssid
        │   │       ├─ Check dedup map → suppress if within window
        │   │       └─ Send on alerts channel (non-blocking; drop if full)
        │   └─ Periodic sweep every 1000 frames
        │
        ├─ On ticker:
        │   └─ sweepDedup() → remove entries older than 2×dedupWindow
        │
        └─ On ctx.Done or frames close:
            └─ close(alerts), return
```

### Deduplication

```
dedup key = eventType + ":" + srcMAC + ":" + bssid  (strings.Builder, hot-path optimized)

For each event:
  1. Compute key
  2. Check map: if exists AND time.Since(lastSeen) < dedupWindow → suppress
  3. Otherwise → send on alerts channel, record lastSeen = now

Periodic cleanup:
  - Every N frames (1000) or ticker (max(dedupWindow, 1s) interval)
  - Remove entries older than 2 × dedupWindow
  - If map exceeds maxDedupEntries (10000), remove oldest half
```

### Shutdown

Engine shutdown is purely cooperative through context and channel closure:
1. `ctx` is cancelled (signal received) OR frames channel is closed
2. Dispatch goroutine exits via `select` case
3. `defer close(e.alerts)` runs
4. Consumers detect closed alerts channel and stop ranging

## Invariants

- Rules are called for every non-nil parsed frame; nil frames are skipped with a warning
- Rule panics are recovered — the engine logs the error and continues processing other rules
- The alerts channel is buffered (configurable size, default 256); overflow drops events with a warning
- The alerts channel is always closed when the dispatch goroutine exits
- Dedup map size is bounded (max 10000 entries); periodic sweep prevents unbounded growth
- `Register()` must be called before `Run()`; the rule list is immutable after `Run()` is called
- Duplicate rule names are rejected at registration time
- Rules that fail `Init()` are not added to the engine
- `floodRule` (unexported) is the shared sliding-window helper for DeauthFloodRule and DisassocFloodRule; new flood-type rules should reuse it
- All rule-specific config structs have `Enabled bool` field; defaults for thresholds/windows are applied via `applyDetectionDefaults()`

## Configuration

| YAML path | Go field | Type | Default | Required |
|-----------|----------|------|---------|----------|
| `detection.enabled` | `DetectionConfig.Enabled` | `bool` | `false` | No |
| `detection.dedup_window` | `DetectionConfig.DedupWindow` | `time.Duration` | `30s` | No |
| `detection.alert_buffer_size` | `DetectionConfig.AlertBufferSize` | `int` | `256` | No |
| `detection.deauth_flood.enabled` | `DeauthFloodConfig.Enabled` | `bool` | `false` | No |
| `detection.deauth_flood.threshold` | `DeauthFloodConfig.Threshold` | `int` | `10` | No |
| `detection.deauth_flood.window` | `DeauthFloodConfig.Window` | `time.Duration` | `10s` | No |
| `detection.disassoc_flood.enabled` | `DisassocFloodConfig.Enabled` | `bool` | `false` | No |
| `detection.disassoc_flood.threshold` | `DisassocFloodConfig.Threshold` | `int` | `10` | No |
| `detection.disassoc_flood.window` | `DisassocFloodConfig.Window` | `time.Duration` | `10s` | No |
| `detection.beacon_flood.enabled` | `BeaconFloodConfig.Enabled` | `bool` | `false` | No |
| `detection.beacon_flood.threshold` | `BeaconFloodConfig.Threshold` | `int` | `50` | No |
| `detection.beacon_flood.window` | `BeaconFloodConfig.Window` | `time.Duration` | `10s` | No |
| `detection.beacon_flood.learning_period` | `BeaconFloodConfig.LearningPeriod` | `time.Duration` | `60s` | No |
| `detection.evil_twin.enabled` | `EvilTwinConfig.Enabled` | `bool` | `false` | No |
| `detection.evil_twin.score_threshold` | `EvilTwinConfig.ScoreThreshold` | `int` | `80` | No |
| `detection.evil_twin.stale_timeout` | `EvilTwinConfig.StaleTimeout` | `time.Duration` | `5m` | No |
| `detection.evil_twin.learning_period` | `EvilTwinConfig.LearningPeriod` | `time.Duration` | `60s` | No |
| `detection.evil_twin.min_beacons` | `EvilTwinConfig.MinBeacons` | `int` | `3` | No |
| `detection.unauthorized_device.enabled` | `UnauthorizedDeviceConfig.Enabled` | `bool` | `false` | No |
| `detection.unauthorized_device.protected_bssids` | `UnauthorizedDeviceConfig.ProtectedBSSIDs` | `[]string` | `[]` | No |
| `detection.unauthorized_device.protected_ssids` | `UnauthorizedDeviceConfig.ProtectedSSIDs` | `[]string` | `[]` | No |
| `detection.unauthorized_device.whitelist` | `UnauthorizedDeviceConfig.Whitelist` | `[]string` | `[]` | No |
| `detection.unauthorized_device.alert_on_probe` | `UnauthorizedDeviceConfig.AlertOnProbe` | `bool` | `false` | No |
| `detection.unauthorized_device.cooldown` | `UnauthorizedDeviceConfig.Cooldown` | `time.Duration` | `5m` | No |

Defaults are applied when fields are zero-valued. Detection validation only applies when `enabled` is true. When `enabled` is false, the engine is not started and a simple frame consumer runs instead.

## Extension Points

- **Adding a new detection rule:** implement the `Rule` interface, call `engine.Register(myRule)` before `engine.Run()`
- **Custom dedup logic:** modify `dedupKey()` to include additional fields (SSID, channel)
- **Alert consumer:** range over `engine.Alerts()` in a goroutine — feed into storage, notifications, API
- **Rule-specific configuration:** add nested config structs under `config.DetectionConfig`; each rule reads its own parameters in `Init()`

## Related Specs

- [802.11 Frame Parser](parser.md) — `ParsedFrame` is the input to all detection rules
- [Capture Pipeline](capture.md) — `Pipeline.Frames()` feeds the detection engine
- [Configuration](configuration.md) — `DetectionConfig` drives engine parameters
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — Engine is created, registered, and started by `cmd/tobimaru`

## Detection Rules

### Deauth Flood (deauth_flood)
- Uses shared `floodRule` helper (`internal/detector/rule_flood.go`) parameterized with `FrameTypeDeauth`.
- Tracks deauthentication frame counts per SrcMAC/BSSID pair within a sliding window.
- Tracking key: `SrcMAC:BSSID` (or just `SrcMAC` if BSSID is empty).
- Severity: `SeverityCritical`.
- Upon threshold breach, emits one event per key and resets the tracker window.
- Internal tracker cap at 2×threshold prevents OOM under burst attacks; real frame count and duration are captured before capping.

### Disassoc Flood (disassoc_flood)
- Uses shared `floodRule` helper parameterized with `FrameTypeDisassoc`.
- Identical tracking logic to deauth flood — differs only in `FrameType` filter.
- Severity: `SeverityCritical`.
- Emitted events include `reason_code`, `threshold`, `window`, and `broadcast` flag in metadata.

### Beacon Flood (beacon_flood)
- Tracks unique BSSIDs per channel within a sliding window.
- Suppresses alerts during a configurable learning period (populates known BSSID set).
- When `>80%` of beacons in the detection window share a common RSSI, `common_rssi` is reported in metadata as a fingerprint indicator.
- Emitted events populate `SrcMAC` and `BSSID` from the triggering frame; dedup keys are therefore per (`SrcMAC`, `BSSID`) pair.

### Evil Twin (evil_twin)
- Compares AP records sharing the same SSID; computes a similarity score.
- Scoring weights:
  - Base: 50 (BSSID mismatch is always present)
  - Channel mismatch: +30
  - RSN IE (id 48) mismatch: +40
  - Vendor IE (id 221) mismatch: +20
  - Capability field mismatch: +20
  - HT Capabilities IE (id 45) mismatch: +10
  - VHT Capabilities IE (id 191) mismatch: +10
  - Extended Capabilities IE (id 127) mismatch: +5
- Default score threshold: 80. The HT/VHT/Extended IE weights (added together: up to +25) can push candidate AP pairs from below-threshold (e.g. 75) to above-threshold (100), increasing alert sensitivity.
- **Alert key canonicalization:** BSSIDs are sorted lexicographically before constructing the dedup key (`ssid:b1:b2` where b1 < b2). This makes duplicate suppression order-independent — the same AP pair suppresses alerts regardless of which was discovered first.

### Unauthorized Device (unauthorized_device)
- Detects unknown MAC addresses attempting to associate with or probe protected access points.
- Protected targets are defined by either `protected_bssids` (MAC addresses) or `protected_ssids` (network names for probe request detection).
- Frame type filter: `AssocReq`, `ReassocReq`, `Auth` (BSSID-based); `ProbeRequest` (SSID-based, only when `alert_on_probe: true`).
- Whitelist lookup: known MACs bypass detection entirely.
- Internal cooldown per SrcMAC (default 5m): suppresses repeated alerts for the same device.
- Severity: `SeverityWarning`.
- Require at least one `protected_bssid` or `protected_ssid` when `enabled: true`.
- `alert_on_probe: true` requires at least one `protected_ssid` to be configured.
