# Contract: Main ↔ Internal Packages

## Boundary Rule

`cmd/tobimaru/main.go` is the SOLE consumer of all `internal/` packages. It wires them together in a specific initialization order. No `internal/` package may import `cmd/tobimaru` or know about the `main` package's existence.

## Interfaces

| Interface | Package | Consumed By | Purpose |
|-----------|---------|-------------|---------|
| `config.Load(path string) (*Config, error)` | `internal/config` | `cmd/tobimaru` | Load and validate config from YAML file |
| `logging.New(cfg config.LogConfig) *slog.Logger` | `internal/logging` | `cmd/tobimaru` | Create configured logger |
| `shutdown.NewManager() *Manager` | `internal/shutdown` | `cmd/tobimaru` | Create signal-aware shutdown coordinator |
| `shutdown.Manager.Register(name, fn)` | `internal/shutdown` | `cmd/tobimaru` | Register cleanup hooks for components |
| `shutdown.Manager.WaitForSignal(ctx)` | `internal/shutdown` | `cmd/tobimaru` | Block until OS signal received |
| `shutdown.Manager.Shutdown(ctx) error` | `internal/shutdown` | `cmd/tobimaru` | Execute cleanup hooks with timeout |
| `version.String() string` | `internal/version` | `cmd/tobimaru` | Formatted version string for --version flag and startup log |
| `version.Version`, `version.Commit`, `version.Date` (vars) | `internal/version` | `cmd/tobimaru` | Individual version fields for structured logging |
| `capture.NewPipeline(cfg) (*Pipeline, error)` | `internal/capture` | `cmd/tobimaru` | Create capture pipeline from config |
| `capture.Pipeline.Start(ctx) error` | `internal/capture` | `cmd/tobimaru` | Start frame capture, parsing, and channel hopping |
| `capture.Pipeline.Stop()` | `internal/capture` | `cmd/tobimaru` | Disable monitor mode and restore interface |
| `capture.Pipeline.Frames() <-chan *parser.ParsedFrame` | `internal/capture` | `cmd/tobimaru` | Read-only channel of parsed frames for consumers |
| `capture.Pipeline.Capabilities() platform.Capabilities` | `internal/capture` | `cmd/tobimaru` (future API) | Platform capabilities detected at pipeline creation |
| `detector.NewEngine(cfg DetectionConfig) *Engine` | `internal/detector` | `cmd/tobimaru` | Create detection engine from config |
| `detector.Engine.Register(rule Rule) error` | `internal/detector` | `cmd/tobimaru` | Register detection rules before starting |
| `detector.Engine.Run(ctx, frames)` | `internal/detector` | `cmd/tobimaru` | Start dispatch goroutine reading from pipeline frames |
| `detector.Engine.Alerts() <-chan *SecurityEvent` | `internal/detector` | `cmd/tobimaru` | Read-only channel of security alerts |
| `platform.Detect() Capabilities` | `internal/platform` | `internal/capture` | Runtime detection of platform features and limitations |

## Initialization

The full startup sequence in `cmd/tobimaru/main.go`:

```go
// 1. Parse flags
flag.Parse()

// 2. Handle --version (exit early, no deps needed)
if *flagVersion { fmt.Println(version.String()); return }

// 3. Load config (pulls from all config sections including capture)
cfg, err := config.Load(*flagConfig)
// On failure: fmt.Fprintf(stderr) + os.Exit(1)

// 4. Initialize logger (consumes only cfg.Log subset)
logger := logging.New(cfg.Log)
slog.SetDefault(logger)

// 5. Log startup info (uses version vars from ldflags)
slog.Info("starting", "version", version.Version, ...)

// 6. Create capture pipeline from full config
pipeline, err := capture.NewPipeline(cfg)
// On failure: slog.Error + os.Exit(1) (logger is available)

// 7. Create shutdown manager and get signal context
sm := shutdown.NewManager()
signalCtx := sm.WaitForSignal(context.Background())

// 8. Start capture pipeline (enables monitor mode, opens pcap, starts goroutines)
pipeline.Start(signalCtx)
// On failure: slog.Error + os.Exit(1)

// 9. Register cleanup hooks (pipeline stop)
sm.Register("capture_stop", func() error { pipeline.Stop(); return nil })

// 10. Create and start detection engine
engine := detector.NewEngine(cfg.Detection)
if cfg.Detection.Enabled {
    engine.Run(signalCtx, pipeline.Frames())
    go consumeAlerts(signalCtx, engine.Alerts())
    sm.Register("detector_stop", func() error { return nil })
} else {
    go consumeFrames(signalCtx, pipeline.Frames())
}

// 11. Block until signal
<-signalCtx.Done()

// 12. Shutdown
slog.Info("shutting down...")
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
if err := sm.Shutdown(shutdownCtx); err != nil { os.Exit(1) }
slog.Info("shutdown complete")
```

## Data Flow Across Boundary

```
cmd/tobimaru/main.go
    │
    │  config.Load(path) ──────────► *config.Config
    │  logging.New(cfg.Log) ───────► *slog.Logger
    │  capture.NewPipeline(cfg) ───► *capture.Pipeline
    │  shutdown.NewManager() ──────► *shutdown.Manager
    │
    │  Pipeline.Start(signalCtx) ──► enables monitor mode, opens pcap, starts goroutines
    │  Pipeline.Frames() ──────────► <-chan *parser.ParsedFrame
    │  detector.NewEngine(cfg.Detection) ──► *detector.Engine
    │  Engine.Run(signalCtx, frames) ──────► starts dispatch goroutine
    │  Engine.Alerts() ────────────► <-chan *detector.SecurityEvent
    │  Manager.Register() ◄──────── cleanup hooks registered during init
    │  Manager.WaitForSignal() ────► context (blocks until signal)
    │  Manager.Shutdown(ctx) ──────► runs hooks (Pipeline.Stop restores interface)
    │
    ▼
*config.Config flows INTO main from internal/config
*slog.Logger flows OUT of main (set as default, used by all code)
*capture.Pipeline lives inside main, started and stopped by main
*detector.Engine lives inside main, created and started by main
<-chan *parser.ParsedFrame flows from pipeline into engine.Run() (or consumeFrames when detection disabled)
<-chan *detector.SecurityEvent flows from engine into consumeAlerts goroutine
*shutdown.Manager lives inside main, receives hooks from components
```

Direction: `internal/*` → `cmd/tobimaru` (all imports go UP to main). `cmd/tobimaru` is the orchestrator: it creates, starts, and stops all components.

## Error Propagation

- Config loading failure → `os.Exit(1)` via `fmt.Fprintf(stderr)` — no graceful shutdown needed (nothing initialized yet)
- Pipeline creation failure → `slog.Error` + `os.Exit(1)` — logger is available, config was loaded
- Pipeline start failure → `slog.Error` + `os.Exit(1)` — monitor mode or pcap handle could not be opened
- Shutdown failure → `os.Exit(1)` after logging the error
- Individual hook failures during shutdown → aggregated via `errors.Join`, does NOT prevent other hooks from running
- Context deadline exceeded during shutdown → remaining hooks are skipped, shutdown returns immediately with error

## Breaking Change Checklist

If you add a new `internal/` package:
- [ ] Add import to `cmd/tobimaru/main.go`
- [ ] Call initialization function in the startup sequence
- [ ] Register cleanup hook with `shutdown.Manager`
- [ ] Add sentinel error handling if the package can fail at init

If you change the startup sequence:
- [ ] Ensure config is loaded before any component that reads config
- [ ] Ensure capture pipeline is created after config (needs `*config.Config`)
- [ ] Ensure logger is initialized before any component that logs at startup
- [ ] Ensure shutdown manager exists before any components register hooks
- [ ] Ensure WaitForSignal is NOT called after hooks are registered (register first)
- [ ] Update `internal/config`'s validation if new required fields affect startup

If you change config structure:
- [ ] All internal packages consuming config types must be updated
- [ ] `configs/tobimaru.yaml` sample must reflect new structure
- [ ] `applyDefaults()` must fill new zero-value fields
- [ ] `validate()` must check new constraints
