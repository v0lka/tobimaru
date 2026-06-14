# Configuration

## Purpose

Loads, validates, and applies defaults to the YAML configuration file. Provides strongly-typed config structs that the rest of the application consumes.

## Key Files

- `internal/config/config.go` — Config structs, `Load()` and `LoadReader()` functions, sentinel errors, constants
- `internal/config/defaults.go` — `applyDefaults()`, default channel lists (`DefaultChannels2GHz`, `DefaultChannels5GHz`, `DefaultPrimaryChannels`) used as fallback at pipeline creation
- `internal/config/validation.go` — `validate()`, `IsValidationError()`, whitelist-based enum validation
- `internal/config/config_test.go` — unit tests covering happy path, missing required fields, invalid enums, unknown fields, defaults
- `configs/tobimaru.yaml` — annotated sample configuration

## Core Types

```go
type Config struct {
    Log       LogConfig       `yaml:"log"`
    Monitor   MonitorConfig   `yaml:"monitor"`
    Detection DetectionConfig `yaml:"detection"`
    State     StateConfig     `yaml:"state"`
    Whitelist WhitelistConfig `yaml:"whitelist"`
    Storage   StorageConfig   `yaml:"storage"`
    API       APIConfig       `yaml:"api"`
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
    Enabled         *bool   `yaml:"enabled"          json:"enabled,omitempty"` // enable weighted dwell (default true)
    PrimaryChannels []int   `yaml:"primary_channels" json:"primary_channels"`  // channels to spend more time on
    Multiplier      float64 `yaml:"multiplier"       json:"multiplier"`        // time multiplier for primary channels
}

type APIConfig struct {
    Enabled         bool          `yaml:"enabled"`          // master switch for HTTP API
    Listen          string        `yaml:"listen"`           // bind address (host:port)
    ReadTimeout     time.Duration `yaml:"read_timeout"`     // max duration for reading request
    WriteTimeout    time.Duration `yaml:"write_timeout"`    // max duration for writing response
    IdleTimeout     time.Duration `yaml:"idle_timeout"`     // keep-alive idle timeout
    ShutdownTimeout time.Duration `yaml:"shutdown_timeout"` // graceful shutdown timeout
    CORS            CORSConfig    `yaml:"cors"`             // CORS settings
    Auth            AuthConfig    `yaml:"auth"`             // authentication configuration
}

type CORSConfig struct {
    AllowedOrigins []string `yaml:"allowed_origins"` // allowed origins; empty = same-origin
}

type AuthConfig struct {
    Enabled           bool          `yaml:"enabled"             json:"enabled"`              // toggle authentication
    SessionTTL        time.Duration `yaml:"session_ttl"         json:"session_ttl"`          // session token lifetime
    AdminPasswordHash string        `yaml:"admin_password_hash" json:"admin_password_hash"`  // bcrypt hash of admin password
    UserPasswordHash  string        `yaml:"user_password_hash"  json:"user_password_hash"`   // bcrypt hash of user password (optional)
    CookieSecure      *bool         `yaml:"cookie_secure"       json:"cookie_secure,omitempty"` // Secure cookie attr (default true)
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
    ErrInvalidStateTTL         = errors.New("state.ttl must be positive when state is enabled (0 uses default; negative is rejected)")
    ErrInvalidSweepInterval    = errors.New("state.sweep_interval must be positive when state is enabled (0 uses default; negative is rejected)")
    ErrInvalidStoragePath      = errors.New("storage.path is required when storage is enabled")
    ErrInvalidSnapshotInterval = errors.New("storage.snapshot_interval must be positive when storage is enabled (0 uses default; negative is rejected)")
    ErrInvalidMaxSnapshots     = errors.New("storage.max_snapshots must be >= 0 when storage is enabled (0 uses default; negative is rejected)")
    ErrInvalidMaxEvents        = errors.New("storage.max_events must be >= 0 when storage is enabled (0 uses default; negative is rejected)")
    ErrInvalidLearningDuration = errors.New("whitelist.auto_learning.duration must be positive when enabled (0 uses default; negative is rejected)")
    ErrInvalidAPIListen        = errors.New("api.listen must be a valid host:port when api is enabled")
    ErrInvalidAPITimeout       = errors.New("api.{read,write,idle,shutdown}_timeout must be positive when api is enabled")
    ErrMissingAdminHash        = errors.New("api.auth.admin_password_hash is required when api.auth is enabled")
    ErrInvalidPasswordHash     = errors.New("api.auth password hash must look like a bcrypt hash ($2a$..., $2b$..., or $2y$...)")
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
    DefaultTimeout         = 100 * time.Millisecond
    DefaultFrameBufferSize = 1024
    DefaultPromiscuous     = true
    DefaultDwellTime       = 300 * time.Millisecond
    DefaultWeightedDwell   = true
    DefaultMultiplier      = 2.5
    DefaultDedupWindow     = 30 * time.Second
    DefaultAlertBufferSize = 256

    DefaultDeauthFloodThreshold = 10
    DefaultDeauthFloodWindow    = 10 * time.Second

    DefaultDisassocFloodThreshold = 10
    DefaultDisassocFloodWindow    = 10 * time.Second

    DefaultBeaconFloodThreshold      = 50
    DefaultBeaconFloodWindow         = 10 * time.Second
    DefaultBeaconFloodLearningPeriod = 60 * time.Second

    DefaultEvilTwinScoreThreshold = 80
    DefaultEvilTwinStaleTimeout   = 5 * time.Minute
    DefaultEvilTwinLearningPeriod = 60 * time.Second
    DefaultEvilTwinMinBeacons     = 3

    DefaultUnauthorizedDeviceCooldown = 5 * time.Minute

    DefaultStateTTL           = 10 * time.Minute
    DefaultStateSweepInterval = 1 * time.Minute

    DefaultAutoLearningDuration = 15 * time.Minute

    DefaultStoragePath         = "tobimaru.db"
    DefaultSnapshotInterval    = 5 * time.Minute
    DefaultMaxSnapshots        = 288
    DefaultMaxEvents           = 100000

    DefaultAPIListen          = "127.0.0.1:8080"
    DefaultAPIReadTimeout     = 15 * time.Second
    DefaultAPIWriteTimeout    = 30 * time.Second
    DefaultAPIIdleTimeout     = 60 * time.Second
    DefaultAPIShutdownTimeout = 5 * time.Second
    DefaultAPISessionTTL      = 24 * time.Hour
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
  │     │     ├─ monitor.channel_hopping.weighted_dwell.multiplier → DefaultMultiplier (if 0)
│     │     ├─ detection.dedup_window    → DefaultDedupWindow     (if 0)
│     │     ├─ detection.alert_buffer_size → DefaultAlertBufferSize (if 0)
│     │     ├─ state.ttl                  → DefaultStateTTL           (if 0)
│     │     ├─ state.sweep_interval       → DefaultStateSweepInterval (if 0)
│     │     ├─ whitelist.auto_learning.duration → DefaultAutoLearningDuration (if 0)
│     │     ├─ storage.path               → DefaultStoragePath        (if empty)
│     │     ├─ storage.snapshot_interval  → DefaultSnapshotInterval   (if 0)
│     │     ├─ storage.max_snapshots      → DefaultMaxSnapshots       (if 0)
│     │     └─ storage.max_events         → DefaultMaxEvents          (if 0)
  │     │
  │     └─► validate(&cfg)
  │           ├─ monitor.interface must be non-empty
  │           ├─ log.level must be in {debug, info, warn, error}
  │           ├─ log.format must be in {text, json}
  │           ├─ monitor.capture.snaplen must be > 0
  │           ├─ monitor.capture.buffer_size must be > 0
  │           ├─ monitor.capture.timeout must be > 0
  │           ├─ state.ttl must be > 0                       (only when state.enabled)
  │           ├─ state.sweep_interval must be > 0            (only when state.enabled)
  │           ├─ storage.path must be non-empty              (only when storage.enabled)
  │           ├─ storage.snapshot_interval must be > 0       (only when storage.enabled)
  │           └─ whitelist.auto_learning.duration must be > 0 (only when auto_learning.enabled)
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
- Because `applyDefaults` runs before `validate`, an explicit `0` (or empty string) for a field that has a default is silently replaced with the default. The "must be positive" validation errors therefore only fire on explicitly negative values that survive defaulting.
- Channel lists (`channels_2ghz`, `channels_5ghz`, `primary_channels`) are an exception — they are left nil by `applyDefaults` and populated at pipeline creation from hardware-supported channels or built-in defaults. This ensures the hopper only attempts channels the adapter actually supports.

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
| `monitor.channel_hopping.channels_2ghz` | `ChannelHoppingConfig.Channels2GHz` | `[]int` | auto (hardware or 1–13) | No |
| `monitor.channel_hopping.channels_5ghz` | `ChannelHoppingConfig.Channels5GHz` | `[]int` | auto (hardware or UNII-1/3) | No |
| `monitor.channel_hopping.include_5ghz` | `ChannelHoppingConfig.Include5GHz` | `bool` | `false` | No |
| `monitor.channel_hopping.weighted_dwell.enabled` | `WeightedDwellConfig.Enabled` | `*bool` | `true` | No |
| `monitor.channel_hopping.weighted_dwell.primary_channels` | `WeightedDwellConfig.PrimaryChannels` | `[]int` | `[1, 6, 11]` | No |
| `monitor.channel_hopping.weighted_dwell.multiplier` | `WeightedDwellConfig.Multiplier` | `float64` | `2.5` | No |
| `detection.enabled` | `DetectionConfig.Enabled` | `bool` | `false` | No |
| `detection.dedup_window` | `DetectionConfig.DedupWindow` | `time.Duration` | `30s` | No |
| `detection.alert_buffer_size` | `DetectionConfig.AlertBufferSize` | `int` | `256` | No |
| `state.enabled` | `StateConfig.Enabled` | `bool` | `false` | No |
| `state.ttl` | `StateConfig.TTL` | `time.Duration` | `10m` | No |
| `state.sweep_interval` | `StateConfig.SweepInterval` | `time.Duration` | `1m` | No |
| `whitelist.auto_learning.enabled` | `AutoLearningConfig.Enabled` | `bool` | `false` | No |
| `whitelist.auto_learning.duration` | `AutoLearningConfig.Duration` | `time.Duration` | `15m` | No |
| `storage.enabled` | `StorageConfig.Enabled` | `bool` | `false` | No |
| `storage.path` | `StorageConfig.Path` | `string` | `"tobimaru.db"` | No |
| `storage.snapshot_interval` | `StorageConfig.SnapshotInterval` | `time.Duration` | `5m` | No |
| `storage.max_snapshots` | `StorageConfig.MaxSnapshots` | `int` | `288` | No |
| `storage.max_events` | `StorageConfig.MaxEvents` | `int` | `100000` | No |
| `api.enabled` | `APIConfig.Enabled` | `bool` | `false` | No |
| `api.listen` | `APIConfig.Listen` | `string` | `"127.0.0.1:8080"` | No |
| `api.read_timeout` | `APIConfig.ReadTimeout` | `time.Duration` | `15s` | No |
| `api.write_timeout` | `APIConfig.WriteTimeout` | `time.Duration` | `30s` | No |
| `api.idle_timeout` | `APIConfig.IdleTimeout` | `time.Duration` | `60s` | No |
| `api.shutdown_timeout` | `APIConfig.ShutdownTimeout` | `time.Duration` | `5s` | No |
| `api.cors.allowed_origins` | `CORSConfig.AllowedOrigins` | `[]string` | `[]` (same-origin) | No |
| `api.auth.enabled` | `AuthConfig.Enabled` | `bool` | `false` | No |
| `api.auth.session_ttl` | `AuthConfig.SessionTTL` | `time.Duration` | `24h` | No |
| `api.auth.admin_password_hash` | `AuthConfig.AdminPasswordHash` | `string` | — | When auth enabled |
| `api.auth.user_password_hash` | `AuthConfig.UserPasswordHash` | `string` | `""` (disabled) | No |
| `api.auth.cookie_secure` | `AuthConfig.CookieSecure` | `*bool` | `true` | No |

## Extension Points

- **Adding a new config section:** define a new `*Config` struct, add it as a field on `Config` with a `yaml` tag, add validation rules in `validate()`, add defaults in `applyDefaults()`
- **Adding a new validation rule:** add a check in `validate()`, append to `errs` slice, create a sentinel error var
- **Adding a new default value:** add the assignment in `applyDefaults()`, define a `Default*` constant

## Related Specs

- [Logging](logging.md) — consumes `LogConfig` to create `*slog.Logger`
- [Capture Engine](capture.md) — consumes `CaptureConfig` and `ChannelHoppingConfig`
- [Network State](state.md) — consumes `StateConfig` and `WhitelistConfig`
- [Storage](storage.md) — consumes `StorageConfig`
- [Contract: Config → Logging](../contracts/config-logging.md) — `LogConfig` type crossing the boundary
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — full `*config.Config` passed to components
- [Detection Engine](detection.md) — consumes `DetectionConfig` for engine parameters
- [ADR-001: YAML Config with KnownFields](../decisions/001-yaml-config.md) — why YAML and strict parsing
