# Detection Engine

## Purpose

Provides WiFi intrusion detection by aggregating detection rules, dispatching parsed 802.11 frames to all registered rules, deduplicating security events, and emitting alerts on a channel. Rules are pure functions that analyze frames and return security events when attack patterns are detected.

## Key Files

- `internal/detector/detector.go` — `Engine` aggregator, dispatch goroutine, deduplication logic
- `internal/detector/rule.go` — `Rule` interface definition
- `internal/detector/event.go` — `SecurityEvent` struct, `Severity` enum
- `internal/detector/event_test.go` — tests for severity ordering, event construction
- `internal/detector/rule_test.go` — tests for rule interface compliance
- `internal/detector/detector_test.go` — tests for engine dispatch, dedup, lifecycle, shutdown
- `internal/config/config.go` — `DetectionConfig` struct (engine-level configuration)
- `internal/config/defaults.go` — detection defaults (dedup_window=30s, alert_buffer_size=256)

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
func (e *Engine) Run(ctx context.Context, frames <-chan *parser.ParsedFrame)
func (e *Engine) Alerts() <-chan *SecurityEvent
```

- `NewEngine(cfg)` — creates engine with buffered alerts channel and dedup map
- `Register(rule)` — validates rule name uniqueness and calls `rule.Init(cfg)`; returns error on duplicate name or init failure
- `Run(ctx, frames)` — starts dispatch goroutine (reading frames, dispatching to rules, deduplicating, emitting alerts). Returns immediately. Goroutine exits on ctx cancellation or frames channel close.
- `Alerts()` — returns read-only alerts channel; closes when dispatch goroutine exits

### DetectionConfig

```go
type DetectionConfig struct {
    Enabled         bool          `yaml:"enabled"`
    DedupWindow     time.Duration `yaml:"dedup_window"`
    AlertBufferSize int           `yaml:"alert_buffer_size"`
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
dedup key = fmt.Sprintf("%s:%s:%s", event.EventType, event.SrcMAC, event.BSSID)

For each event:
  1. Compute key
  2. Check map: if exists AND time.Since(lastSeen) < dedupWindow → suppress
  3. Otherwise → send on alerts channel, record lastSeen = now

Periodic cleanup:
  - Every N frames (1000) or ticker (dedupWindow interval)
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

## Configuration

| YAML path | Go field | Type | Default | Required |
|-----------|----------|------|---------|----------|
| `detection.enabled` | `DetectionConfig.Enabled` | `bool` | `false` | No |
| `detection.dedup_window` | `DetectionConfig.DedupWindow` | `time.Duration` | `30s` | No |
| `detection.alert_buffer_size` | `DetectionConfig.AlertBufferSize` | `int` | `256` | No |

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
