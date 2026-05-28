# WiFi Capture Engine

## Purpose

Provides live 802.11 frame capture via gopacket/pcap on Linux and macOS. Manages monitor mode switching, per-channel capture with weighted dwell time hopping, and a pipeline that parses frames and delivers them to consumers through a channel. Adapts behavior based on platform capabilities (dwell enforcement, injection availability).

## Key Files

- `internal/capture/capture.go` — `CaptureHandle` wrapping pcap handle, `OpenCapture()` with RFMon + BPF filter (platform-agnostic; works on Linux and macOS via gopacket/pcap)
- `internal/capture/monitor.go` — `MonitorModeManager` interface and `ErrNotSupported` sentinel
- `internal/capture/monitor_linux.go` — Linux implementation via `iw`/`ip` commands (build tag: `linux`)
- `internal/capture/monitor_darwin.go` — macOS implementation via `airport` utility (build tag: `darwin`)
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

`OpenCapture()` creates an inactive pcap handle, sets snaplen, promiscuous mode, timeout, RFMon mode (`SetRFMon(true)`), and buffer size, then activates the handle and applies a BPF filter for management/control/data frames (`type mgt or type ctl or type data`). Fails if the interface does not support monitor mode capturing.

**Monitor mode management:**
```go
type MonitorModeManager interface {
    EnableMonitor(iface string) error
    DisableMonitor(iface string) error
    SetChannel(iface string, channel int) error
    IsSupported() bool
}

var ErrNotSupported = errors.New("monitor mode is not supported on this platform")
```

On Linux, `EnableMonitor()` uses `iw dev <iface> set type monitor` + `ip link set <iface> up`. `SetChannel()` uses `iw dev <iface> set channel <n>`. On macOS, `EnableMonitor()` uses `airport <iface> -z` to disconnect before RFMon activation; `SetChannel()` uses `airport <iface> --channel=<N>` (1-3s overhead). On other platforms, all methods return `ErrNotSupported`.

**Channel hopper:**
```go
type ChannelHopper struct { /* internal state */ }

func NewChannelHopper(cfg *config.ChannelHoppingConfig) (*ChannelHopper, error)
func (h *ChannelHopper) Next() (channel int, dwell time.Duration)
func (h *ChannelHopper) Reset()
func (h *ChannelHopper) ChannelCount() int
func (h *ChannelHopper) Run(ctx context.Context, setFn func(channel int) error)
```

`NewChannelHopper()` builds the channel list from 2.4 GHz (channels 1-13 by default) and optionally 5 GHz (channels 36-165). Primary channels (default: 1, 6, 11) receive extended dwell time via the configured multiplier (default 2.5x). `Run()` executes the hopping loop: call `setFn` to switch channel, wait for dwell duration, repeat. Blocks until `ctx` is canceled. Returns an error if hopping is disabled or no channels are configured.

**Pipeline:**
```go
type Pipeline struct { /* internal state */ }

func NewPipeline(cfg *config.Config) (*Pipeline, error)
func (p *Pipeline) Start(ctx context.Context) error
func (p *Pipeline) Stop()
func (p *Pipeline) Frames() <-chan *parser.ParsedFrame
func (p *Pipeline) Capabilities() platform.Capabilities
```

`NewPipeline()` detects platform capabilities via `platform.Detect()`, logs them and any limitations, and enforces a minimum dwell time of 1 second on platforms with slow channel switching (macOS). If frame injection is unavailable, a warning is logged. `Capabilities()` returns the detected capabilities for use by consumers (e.g., future REST API).

## Flow

### Startup

```
NewPipeline(cfg)
  │
  ├─► Create MonitorModeManager for current platform
  │
  ├─► Detect platform capabilities via platform.Detect()
  │     ├─ Log capabilities at INFO level
  │     ├─ Log injection unavailability warning if !FrameInjection
  │     └─ Log all platform limitations
  │
  ├─► If channel hopping enabled and SlowHopping:
  │     └─ Enforce minimum dwell of 1s (log WARNING if overridden)
  │
  ├─► If channel hopping enabled:
  │     └─ Create ChannelHopper from ChannelHoppingConfig
  │
  └─► Return Pipeline with frames channel (buffer cap: 1024)

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
Pipeline.Stop()
  └─► If supported: DisableMonitor(iface) → restore managed mode
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
- The frames channel has a fixed buffer capacity of 1024 and is closed by the capture goroutine when it exits
- The capture goroutine always closes the frames channel on exit (via `defer close(p.frames)`)
- Channel hopping errors are logged as warnings — a failed channel switch does NOT stop the pipeline
- Parse errors are logged at debug level — malformed frames are skipped but do NOT block the pipeline
- Unknown frame types are silently dropped — only classified frames reach consumers
- Context cancellation closes the pcap handle in a separate goroutine, which unblocks `NextPacket()` and allows the capture goroutine to exit cleanly
- `Stop()` is idempotent — it checks `IsSupported()` before attempting interface operations

## Configuration

| YAML path | Go field | Type | Default | Required |
|-----------|----------|------|---------|----------|
| `monitor.capture.snaplen` | `CaptureConfig.Snaplen` | `int` | `65535` | No |
| `monitor.capture.buffer_size` | `CaptureConfig.BufferSize` | `int` | `2097152` (2 MB) | No |
| `monitor.capture.promiscuous` | `CaptureConfig.Promiscuous` | `bool` | `true` | No |
| `monitor.capture.timeout` | `CaptureConfig.Timeout` | `time.Duration` | `100ms` | No |
| `monitor.channel_hopping.enabled` | `ChannelHoppingConfig.Enabled` | `bool` | — | No |
| `monitor.channel_hopping.dwell` | `ChannelHoppingConfig.Dwell` | `time.Duration` | `300ms` | No |
| `monitor.channel_hopping.channels_2ghz` | `ChannelHoppingConfig.Channels2GHz` | `[]int` | `[1..13]` | No |
| `monitor.channel_hopping.channels_5ghz` | `ChannelHoppingConfig.Channels5GHz` | `[]int` | UNII-1/2/2e/3 | No |
| `monitor.channel_hopping.include_5ghz` | `ChannelHoppingConfig.Include5GHz` | `bool` | `false` | No |
| `monitor.channel_hopping.weighted_dwell.enabled` | `WeightedDwellConfig.Enabled` | `bool` | — | No |
| `monitor.channel_hopping.weighted_dwell.primary_channels` | `WeightedDwellConfig.PrimaryChannels` | `[]int` | `[1, 6, 11]` | No |
| `monitor.channel_hopping.weighted_dwell.multiplier` | `WeightedDwellConfig.Multiplier` | `float64` | `2.5` | No |

## Extension Points

- **Adding a new capture backend for another platform (e.g., BSD, Windows):** implement `MonitorModeManager` for the new platform with appropriate build tags, add a platform capabilities variant
- **Adding a new channel hopping strategy:** extend `ChannelHopper` with new dwell modes (adaptive, band-priority)
- **Adding BPF filter customization:** expose `filter` in config or derive from config settings
- **Adding pipeline metrics:** track frames captured/dropped/errored in the capture loop via counters or channel

## Related Specs

- [802.11 Frame Parser](parser.md) — `parser.Parse()` is called in the capture loop
- [Configuration](configuration.md) — `CaptureConfig` and `ChannelHoppingConfig` drive the pipeline
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — `Pipeline` is created, started, and stopped by `cmd/tobimaru`
