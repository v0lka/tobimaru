# WiFi Capture Engine

## Purpose

Provides live 802.11 frame capture via gopacket/pcap on Linux and macOS. Manages monitor mode switching, per-channel capture with weighted dwell time hopping, and a pipeline that parses frames and delivers them to consumers through a channel. Adapts behavior based on platform capabilities (dwell enforcement, injection availability).

## Key Files

- `internal/capture/capture.go` — `CaptureHandle` wrapping pcap handle, `OpenCapture()` with RFMon activation (platform-agnostic; works on Linux and macOS via gopacket/pcap)
- `internal/capture/monitor.go` — `MonitorModeManager` interface and `ErrNotSupported` sentinel
- `internal/capture/monitor_linux.go` — Linux implementation via `iw`/`ip` commands (build tag: `linux`)
- `internal/capture/monitor_darwin.go` — macOS implementation via CoreWLAN cgo bridge + BPF `SetRFMon` (build tag: `darwin`)
- `internal/capture/monitor_darwin.m` — CoreWLAN Objective-C bridge: `SetInterfaceChannel()` and `GetSupportedWLANChannels()` using `CWInterface`/`CWChannel`
- `internal/capture/monitor_unsupported.go` — Stub returning `ErrNotSupported` (build tag: `!linux && !darwin`)
- `internal/capture/channel.go` — `ChannelHopper` with weighted dwell time on primary channels
- `internal/capture/channel_test.go` — tests for create, weighted dwell, disabled, wrap-around, reset, empty channels, 5GHz
- `internal/capture/pipeline.go` — `Pipeline` orchestrating capture, parsing, channel hopping, and platform-aware graceful degradation
- `internal/platform/capabilities.go` — `Capabilities` struct and `ReportLimitations()`
- `internal/platform/capabilities_linux.go` — `Detect()` returning full Linux capabilities
- `internal/platform/capabilities_darwin.go` — `Detect()` returning macOS capabilities (monitor=true, injection=false, slow hopping, single adapter)
- `internal/platform/capabilities_others.go` — `Detect()` returning unsupported for other platforms

## Core Types

**Capture handle:**
```go
type CaptureHandle struct { /* wraps pcap.Handle */ }

func OpenCapture(iface string, snaplen int, promisc bool, timeout time.Duration, bufferSize int) (*CaptureHandle, error)
func (c *CaptureHandle) PacketSource() *gopacket.PacketSource
func (c *CaptureHandle) Close()
```

`OpenCapture()` creates an inactive pcap handle, sets snaplen, promiscuous mode, timeout, RFMon mode (`SetRFMon(true)`), and buffer size, then activates the handle. No BPF filter is applied — an in-kernel `type mgt or type ctl or type data` filter is fundamentally incompatible with variable-length radiotap headers on macOS because the filter checks frame type at a fixed link-layer offset. When the radiotap header length varies between packets (depending on which fields are present), the BPF filter reads the wrong bytes — potentially matching radiotap metadata bytes that happen to resemble management/control/data type values and passing non‑802.11 noise through to gopacket. The Go-level parser validates every frame after gopacket correctly parses the per-packet radiotap length, making the in-kernel filter both redundant and harmful. Fails if the interface does not support monitor mode capturing.

**Monitor mode management:**
```go
func NewMonitorModeManager() (MonitorModeManager, error)

type MonitorModeManager interface {
    EnableMonitor(ctx context.Context, iface string) error
    DisableMonitor(ctx context.Context, iface string) error
    SetChannel(ctx context.Context, iface string, channel int) error
    SupportedChannels(ctx context.Context, iface string) ([]int, error)
    IsSupported() bool
}

var ErrNotSupported = errors.New("monitor mode is not supported on this platform")
```

On Linux, `EnableMonitor()` uses `iw dev <iface> set type monitor` + `ip link set <iface> up`. `SetChannel()` uses `iw dev <iface> set channel <n>`. `SupportedChannels()` returns `(nil, nil)` — the platform cannot enumerate hardware channels; all configured channels are assumed valid. On macOS, `EnableMonitor()` is a no-op (pcap's `SetRFMon(true)` handles the mode switch via BPF `BIOCSRFMON` ioctl); `SetChannel()` uses CoreWLAN via cgo bridge (`setWLANChannel:error:`, 1-3s overhead); `SupportedChannels()` queries CoreWLAN's `supportedWLANChannels` property and returns the actual channel list. On other platforms, all methods return `ErrNotSupported`.

**Channel hopper:**
```go
type ChannelHopper struct { /* internal state */ }

func NewChannelHopper(cfg *config.ChannelHoppingConfig) (*ChannelHopper, error)
func (h *ChannelHopper) Next() (channel int, dwell time.Duration)
func (h *ChannelHopper) Reset()
func (h *ChannelHopper) ChannelCount() int
func (h *ChannelHopper) Run(ctx context.Context, setFn func(channel int) error)
```

`NewChannelHopper()` builds the channel list from 2.4 GHz and optionally 5 GHz channels. Channel lists are optional in configuration — when nil (not set in YAML), the pipeline auto-populates them from hardware-supported channels (macOS via CoreWLAN) or built-in defaults (Linux: channels 1–13 and non-DFS 5 GHz UNII-1 + UNII-3). Explicitly configured channels are intersected with the hardware-supported list to avoid attempting unsupported channels (e.g., DFS channels on macOS adapters). Primary channels (default: 1, 6, 11) receive extended dwell time via the configured multiplier (default 2.5x). `Run()` executes the hopping loop: call `setFn` to switch channel, wait for dwell duration, repeat. Blocks until `ctx` is canceled. Returns an error if hopping is disabled or no channels remain after filtering.

**Pipeline:**
```go
type Pipeline struct { /* internal state */ }

func NewPipeline(cfg *config.Config, logger *slog.Logger) (*Pipeline, error)
func (p *Pipeline) Start(ctx context.Context) error
func (p *Pipeline) Stop(ctx context.Context) error
func (p *Pipeline) Frames() <-chan *parser.ParsedFrame
func (p *Pipeline) Capabilities() platform.Capabilities
func (p *Pipeline) CurrentChannel() int
```

`NewPipeline()` detects platform capabilities via `platform.Detect()`, logs them and any limitations, and enforces a minimum dwell time of 1 second on platforms with slow channel switching (macOS). It queries hardware-supported channels via `SupportedChannels()` and populates channel lists if the user did not configure them explicitly (nil slices in config). Configured channels are then intersected with the hardware list, removing unsupported channels (e.g., DFS channels missing on an Apple adapter). If frame injection is unavailable, an info message is logged. `Capabilities()` returns the detected capabilities for use by consumers (e.g., future REST API). The `logger` parameter allows callers to inject a configured logger for pipeline startup messages.

## Flow

### Startup

```
NewPipeline(cfg, logger)
  │
  ├─► Create MonitorModeManager for current platform
  │
  ├─► Detect platform capabilities via platform.Detect()
  │     ├─ Log capabilities at INFO level via injected logger
  │     ├─ Log injection unavailability info if !FrameInjection
  │     └─ Log all platform limitations
  │
  ├─► If channel hopping enabled and SlowHopping:
  │     └─ Enforce minimum dwell of 1s (log WARNING if overridden)
  │
  ├─► If channel hopping enabled and supported channels available:
  │     ├─ Auto-populate nil channel lists from hardware (macOS) or defaults (Linux)
  │     └─ Intersect configured channels with hardware-supported list (log WARNING on removals)
  │
  ├─► If channel hopping enabled:
  │     └─ Create ChannelHopper from (now populated) ChannelHoppingConfig
  │
  └─► Return Pipeline with frames channel (buffer cap: cfg.Monitor.Capture.FrameBufferSize, default 1024)

Pipeline.Start(ctx)
  │
  ├─► Check IsSupported() — return ErrNotSupported if not
  │
  ├─► EnableMonitor(iface) — switch to monitor mode
  │
  ├─► OpenCapture(iface, snaplen, promiscuous, timeout)
  │
  ├─► Start captureLoop goroutine:
  │     └─ Read packets from pcap → Parse → send on frames channel
  │
  ├─► If channel hopping enabled:
  │     └─ Start channelHopperLoop goroutine:
  │           └─ hopper.Run(ctx, monitor.SetChannel)
  │
  └─► Start context watcher goroutine:
        └─ On ctx.Done(): Close pcap handle
```

### Shutdown

```
Pipeline.Stop(ctx)
  └─► If supported: DisableMonitor(ctx, iface) → restore managed mode
  └─► Returns error if DisableMonitor fails
```

The pipeline is designed for cooperative shutdown: when `Start()`'s context is cancelled, the capture goroutine stops (pcap handle is closed), the frames channel is closed, and the hopper stops. `Stop()` then restores the interface mode.

### Capture loop

```
captureLoop(ctx)
  │
  └─► Loop:
        ├─ Check ctx.Done() → return
        ├─ source.NextPacket()
        │     └─ On error: check ctx, return or log
        ├─ parser.Parse(packet)
        │     └─ On error: log debug, continue
        ├─ Skip FrameTypeUnknown
        └─ Send frame on p.frames channel (non-blocking via select with ctx)
```

## Invariants

- `Pipeline.Start()` enables monitor mode BEFORE opening the pcap handle — opening in RFMon mode requires the interface to be in monitor mode
- Platform capabilities are detected and logged at `NewPipeline()` before any capture operations begin
- On platforms with slow channel switching (`SlowHopping`), dwell time is enforced to a minimum of 1 second
- The frames channel buffer capacity is configured via `CaptureConfig.FrameBufferSize` (default 1024) and is closed by the capture goroutine when it exits
- The capture goroutine always closes the frames channel on exit (via `defer close(p.frames)`)
- Channel hopping errors are logged as warnings — a failed channel switch does NOT stop the pipeline
- Parse errors are logged at debug level — malformed frames are skipped but do NOT block the pipeline
- Unknown frame types are silently dropped — only classified frames reach consumers
- Context cancellation closes the pcap handle in a separate goroutine, which unblocks `NextPacket()` and allows the capture goroutine to exit cleanly
- `Stop()` is idempotent — it checks `IsSupported()` before attempting interface operations
- Channel lists in configuration are optional — nil slices trigger auto-population from hardware-supported channels (macOS via CoreWLAN) or built-in defaults (Linux: 1–13 + non-DFS 5 GHz)
- When hardware-supported channels are available (macOS), all configured channels are intersected with the hardware list before the hopper is created — unsupported channels are never attempted, eliminating repeated `"channel not in supportedWLANChannels"` errors
- `SupportedChannels()` returns `(nil, nil)` on platforms that cannot enumerate channels (Linux, unsupported); the caller treats nil as "all configured channels are valid"

## Configuration

| YAML path | Go field | Type | Default | Required |
|-----------|----------|------|---------|----------|
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
| `monitor.channel_hopping.weighted_dwell.enabled` | `WeightedDwellConfig.Enabled` | `bool` | — | No |
| `monitor.channel_hopping.weighted_dwell.primary_channels` | `WeightedDwellConfig.PrimaryChannels` | `[]int` | `[1, 6, 11]` | No |
| `monitor.channel_hopping.weighted_dwell.multiplier` | `WeightedDwellConfig.Multiplier` | `float64` | `2.5` | No |

## Extension Points

- **Adding a new capture backend for another platform (e.g., BSD, Windows):** implement `MonitorModeManager` for the new platform with appropriate build tags, add a platform capabilities variant
- **Adding a new channel hopping strategy:** extend `ChannelHopper` with new dwell modes (adaptive, band-priority)
- **Adding pipeline metrics:** track frames captured/dropped/errored in the capture loop via counters or channel

## Related Specs

- [802.11 Frame Parser](parser.md) — `parser.Parse()` is called in the capture loop
- [Configuration](configuration.md) — `CaptureConfig` and `ChannelHoppingConfig` drive the pipeline
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — `Pipeline` is created, started, and stopped by `cmd/tobimaru`
