# Configuration

## Purpose

Loads, validates, and applies defaults to the YAML configuration file. Provides strongly-typed config structs that the rest of the application consumes.

## Key Files

- `internal/config/config.go` — Config structs, `Load()` and `LoadReader()` functions, sentinel errors, constants
- `internal/config/defaults.go` — `applyDefaults()`, default channel lists (`DefaultChannels2GHz`, `DefaultChannels5GHz`)
- `internal/config/validation.go` — `validate()`, `IsValidationError()`, whitelist-based enum validation
- `internal/config/config_test.go` — unit tests covering happy path, missing required fields, invalid enums, unknown fields, defaults
- `configs/tobimaru.yaml` — annotated sample configuration

## Core Types

```go
type Config struct {
    Log       LogConfig       `yaml:"log"`
    Monitor   MonitorConfig   `yaml:"monitor"`
    Detection DetectionConfig `yaml:"detection"`
}

type LogConfig struct {
    Level  string `yaml:"level"`  // debug, info, warn, error
    Format string `yaml:"format"` // text, json
}

type MonitorConfig struct {
    Interface      string               `yaml:"interface"`       // WiFi interface name (e.g., wlan0)
    Capture        CaptureConfig        `yaml:"capture"`         // pcap capture settings
    ChannelHopping ChannelHoppingConfig `yaml:"channel_hopping"` // channel hopping settings
}

type CaptureConfig struct {
    Snaplen         int           `yaml:"snaplen"`           // max bytes per packet
    BufferSize      int           `yaml:"buffer_size"`       // pcap buffer size in bytes
    FrameBufferSize int           `yaml:"frame_buffer_size"` // parsed frame channel buffer size
    Promiscuous     *bool         `yaml:"promiscuous"`       // promiscuous mode; defaults to true
    Timeout         time.Duration `yaml:"timeout"`           // pcap read timeout
}

type ChannelHoppingConfig struct {
    Enabled       bool                `yaml:"enabled"`        // enable channel hopping
    Dwell         time.Duration       `yaml:"dwell"`          // base dwell time per channel
    WeightedDwell WeightedDwellConfig `yaml:"weighted_dwell"` // weighted dwell config
    Channels2GHz  []int               `yaml:"channels_2ghz"`  // 2.4 GHz channels
    Channels5GHz  []int               `yaml:"channels_5ghz"`  // 5 GHz channels
    Include5GHz   bool                `yaml:"include_5ghz"`   // include 5 GHz channels
}

type WeightedDwellConfig struct {
    Enabled         bool    `yaml:"enabled"`          // enable weighted dwell
    PrimaryChannels []int   `yaml:"primary_channels"` // channels to spend more time on
    Multiplier      float64 `yaml:"multiplier"`       // time multiplier for primary channels
}
```

**Validation errors:**
```go
var (
    ErrMissingInterface  = errors.New("monitor.interface is required")
    ErrInvalidLogLevel   = errors.New("log.level must be one of: debug, info, warn, error")
    ErrInvalidLogFormat  = errors.New("log.format must be one of: text, json")
    ErrInvalidSnaplen    = errors.New("monitor.capture.snaplen must be positive")
    ErrInvalidBufferSize = errors.New("monitor.capture.buffer_size must be positive")
    ErrInvalidTimeout    = errors.New("monitor.capture.timeout must be positive")
)

type ValidationError struct {
    Errors []error  // wraps multiple field errors via errors.Join
}
```

**Constants:**
```go
const (
    DefaultLogLevel        = "info"
    DefaultLogFormat       = "text"
    DefaultSnaplen         = 65535
    DefaultBufferSize      = 2097152 // 2 MB
    DefaultFrameBufferSize = 1024
    DefaultPromiscuous     = true
    DefaultTimeout         = 100 * time.Millisecond
    DefaultDwellTime       = 300 * time.Millisecond
    DefaultWeightedDwell   = true
    DefaultMultiplier      = 2.5
    DefaultDedupWindow     = 30 * time.Second
    DefaultAlertBufferSize = 256
)
```

## Flow

```
config.Load(path)
  │
  ├─► os.Open(path)
  │     └─ On failure: return error wrapping path
  │
  ├─► LoadReader(io.Reader)
  │     │
  │     ├─► yaml.Decode(&cfg) with KnownFields(true)
  │     │     └─ Rejects unknown YAML keys (catches typos)
  │     │     └─ On failure: return parse error
  │     │
  │     ├─► applyDefaults(&cfg)
  │     │     ├─ log.level                          → DefaultLogLevel        (if empty)
  │     │     ├─ log.format                         → DefaultLogFormat       (if empty)
  │     │     ├─ monitor.capture.snaplen             → DefaultSnaplen         (if 0)
  │     │     ├─ monitor.capture.buffer_size         → DefaultBufferSize      (if 0)
  │     │     ├─ monitor.capture.frame_buffer_size   → DefaultFrameBufferSize (if 0)
  │     │     ├─ monitor.capture.promiscuous         → DefaultPromiscuous     (if nil)
  │     │     ├─ monitor.capture.timeout             → DefaultTimeout         (if 0)
  │     │     ├─ monitor.channel_hopping.dwell       → DefaultDwellTime       (if 0)
  │     │     ├─ monitor.channel_hopping.channels_2ghz → DefaultChannels2GHz() (if nil)
  │     │     ├─ monitor.channel_hopping.channels_5ghz → DefaultChannels5GHz() (if nil)
  │     │     ├─ monitor.channel_hopping.weighted_dwell.multiplier → DefaultMultiplier (if 0)
│     │     ├─ detection.dedup_window    → DefaultDedupWindow     (if 0)
│     │     └─ detection.alert_buffer_size → DefaultAlertBufferSize (if 0)
  │     │
  │     └─► validate(&cfg)
  │           ├─ monitor.interface must be non-empty
  │           ├─ log.level must be in {debug, info, warn, error}
  │           ├─ log.format must be in {text, json}
  │           ├─ monitor.capture.snaplen must be > 0
  │           ├─ monitor.capture.buffer_size must be > 0
  │           └─ monitor.capture.timeout must be > 0
  │           └─ On failure: return *ValidationError
  │
  └─► Return *Config, nil
```

`LoadReader` accepts an `io.Reader` rather than requiring a file path, enabling unit tests to pass strings or byte buffers directly. This isolates config loading from the filesystem.

## Invariants

- `LoadReader` always calls `applyDefaults` before `validate` — defaults fill in before validation checks
- `KnownFields(true)` is always enabled — unknown YAML keys cause a parse error, not silent ignoring
- Validation collects ALL field-level errors before returning, using `ValidationError` with `errors.Join`
- `monitor.interface` is the only required field (checked as non-empty)
- `IsValidationError(err)` returns `true` for `*ValidationError` via `errors.As`
- Defaults are applied only when the corresponding field is the Go zero value (0 for ints and durations, nil for slices, empty string for strings)

## Configuration

| YAML path | Go field | Type | Default | Required |
|-----------|----------|------|---------|----------|
| `log.level` | `LogConfig.Level` | `string` | `"info"` | No |
| `log.format` | `LogConfig.Format` | `string` | `"text"` | No |
| `monitor.interface` | `MonitorConfig.Interface` | `string` | — | **Yes** |
| `monitor.capture.snaplen` | `CaptureConfig.Snaplen` | `int` | `65535` | No |
| `monitor.capture.buffer_size` | `CaptureConfig.BufferSize` | `int` | `2097152` (2 MB) | No |
| `monitor.capture.frame_buffer_size` | `CaptureConfig.FrameBufferSize` | `int` | `1024` | No |
| `monitor.capture.promiscuous` | `CaptureConfig.Promiscuous` | `*bool` | `true` | No |
| `monitor.capture.timeout` | `CaptureConfig.Timeout` | `time.Duration` | `100ms` | No |
| `monitor.channel_hopping.enabled` | `ChannelHoppingConfig.Enabled` | `bool` | — | No |
| `monitor.channel_hopping.dwell` | `ChannelHoppingConfig.Dwell` | `time.Duration` | `300ms` | No |
| `monitor.channel_hopping.channels_2ghz` | `ChannelHoppingConfig.Channels2GHz` | `[]int` | `[1..13]` | No |
| `monitor.channel_hopping.channels_5ghz` | `ChannelHoppingConfig.Channels5GHz` | `[]int` | UNII-1/2/2e/3 | No |
| `monitor.channel_hopping.include_5ghz` | `ChannelHoppingConfig.Include5GHz` | `bool` | `false` | No |
| `monitor.channel_hopping.weighted_dwell.enabled` | `WeightedDwellConfig.Enabled` | `bool` | — | No |
| `monitor.channel_hopping.weighted_dwell.primary_channels` | `WeightedDwellConfig.PrimaryChannels` | `[]int` | `[1, 6, 11]` | No |
| `monitor.channel_hopping.weighted_dwell.multiplier` | `WeightedDwellConfig.Multiplier` | `float64` | `2.5` | No |
| `detection.enabled` | `DetectionConfig.Enabled` | `bool` | `false` | No |
| `detection.dedup_window` | `DetectionConfig.DedupWindow` | `time.Duration` | `30s` | No |
| `detection.alert_buffer_size` | `DetectionConfig.AlertBufferSize` | `int` | `256` | No |

## Extension Points

- **Adding a new config section:** define a new `*Config` struct, add it as a field on `Config` with a `yaml` tag, add validation rules in `validate()`, add defaults in `applyDefaults()`
- **Adding a new validation rule:** add a check in `validate()`, append to `errs` slice, create a sentinel error var
- **Adding a new default value:** add the assignment in `applyDefaults()`, define a `Default*` constant

## Related Specs

- [Logging](logging.md) — consumes `LogConfig` to create `*slog.Logger`
- [Capture Engine](capture.md) — consumes `CaptureConfig` and `ChannelHoppingConfig`
- [Contract: Config → Logging](../contracts/config-logging.md) — `LogConfig` type crossing the boundary
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — full `*config.Config` passed to `capture.NewPipeline()` and `detector.NewEngine()`
- [Detection Engine](detection.md) — consumes `DetectionConfig` for engine parameters (dedup window, alert buffer)
- [ADR-001: YAML Config with KnownFields](../decisions/001-yaml-config.md) — why YAML and strict parsing
