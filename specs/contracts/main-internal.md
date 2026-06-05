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
| `capture.NewPipeline(cfg, logger) (*Pipeline, error)` | `internal/capture` | `cmd/tobimaru` | Create capture pipeline from config |
| `capture.Pipeline.Start(ctx) error` | `internal/capture` | `cmd/tobimaru` | Start frame capture, parsing, and channel hopping |
| `capture.Pipeline.Stop()` | `internal/capture` | `cmd/tobimaru` | Disable monitor mode and restore interface |
| `capture.Pipeline.Frames() <-chan *parser.ParsedFrame` | `internal/capture` | `cmd/tobimaru` | Read-only channel of parsed frames for consumers |
| `capture.Pipeline.Capabilities() platform.Capabilities` | `internal/capture` | `cmd/tobimaru` (future API) | Platform capabilities detected at pipeline creation |
| `detector.NewEngine(cfg DetectionConfig) *Engine` | `internal/detector` | `cmd/tobimaru` | Create detection engine from config |
| `detector.Engine.Register(rule Rule) error` | `internal/detector` | `cmd/tobimaru` | Register detection rules before starting |
| `detector.Engine.Run(ctx, frames)` | `internal/detector` | `cmd/tobimaru` | Start dispatch goroutine reading from pipeline frames |
| `detector.Engine.Alerts() <-chan *SecurityEvent` | `internal/detector` | `cmd/tobimaru` | Read-only channel of security alerts |
| `state.NewEngine(cfg, wlCfg, logger) *Engine` | `internal/state` | `cmd/tobimaru` | Create network state engine from config |
| `state.Engine.ProcessFrame(frame)` | `internal/state` | `cmd/tobimaru` | Update AP/client state from a parsed frame |
| `state.Engine.RunEviction(ctx)` | `internal/state` | `cmd/tobimaru` | Start TTL eviction goroutine |
| `state.Engine.Snapshot() *Snapshot` | `internal/state` | `cmd/tobimaru` | Get point-in-time state copy for persistence |
| `state.Engine.Whitelist() *WhitelistEngine` | `internal/state` | `cmd/tobimaru` | Access whitelist/blacklist engine |
| `state.NewLearningMode(cfg, engine, logger) *LearningMode` | `internal/state` | `cmd/tobimaru` | Create auto-learning controller |
| `state.LearningMode.Run(ctx) []*WhitelistEntry` | `internal/state` | `cmd/tobimaru` | Run learning phase, return generated whitelist |
| `storage.Open(cfg) (*SQLiteRepository, error)` | `internal/storage` | `cmd/tobimaru` | Open SQLite database, run migrations |
| `storage.Repository.SaveEvent(ctx, event) error` | `internal/storage` | `cmd/tobimaru` | Persist a security event |
| `storage.Repository.PruneEvents(ctx, max) (int64, error)` | `internal/storage` | `cmd/tobimaru` | Remove oldest events beyond max count |
| `storage.Repository.SaveSnapshot(ctx, snap) error` | `internal/storage` | `cmd/tobimaru` | Persist a state snapshot |
| `storage.Repository.PruneSnapshots(ctx, max) (int64, error)` | `internal/storage` | `cmd/tobimaru` | Remove old snapshots beyond max count |
| `storage.Repository.ListWhitelist(ctx) ([]*WhitelistEntry, error)` | `internal/storage` | `cmd/tobimaru` | Load persisted whitelist |
| `storage.Repository.ListBlacklist(ctx) ([]*BlacklistEntry, error)` | `internal/storage` | `cmd/tobimaru` | Load persisted blacklist |
| `storage.Repository.SaveWhitelistEntry(ctx, entry) error` | `internal/storage` | `cmd/tobimaru` | Persist a whitelist entry |
| `storage.Repository.Close() error` | `internal/storage` | `cmd/tobimaru` | Close database connection |
| `platform.Detect() Capabilities` | `internal/platform` | `internal/capture` | Runtime detection of platform features and limitations |

## Initialization

The full startup sequence in `cmd/tobimaru/main.go`:

```go
// 1. Parse flags
flag.Parse()

// 2. Handle --version (exit early, no deps needed)
if *flagVersion { fmt.Println(version.String()); return }

// 3. Load config (pulls from all config sections)
cfg, err := config.Load(*flagConfig)
// On failure: fmt.Fprintf(stderr) + os.Exit(1)

// 4. Initialize logger (consumes only cfg.Log subset)
logger := logging.New(cfg.Log)
slog.SetDefault(logger)

// 5. Log startup info (uses version vars from ldflags)
slog.Info("starting", "version", version.Version, ...)

// 6. Open storage (if enabled) — early, before anything that writes to it
var repo storage.Repository
if cfg.Storage.Enabled {
    repo, err = storage.Open(cfg.Storage)
    // On failure: slog.Error + os.Exit(1)
}

// 7. Create state engine (if enabled), load persisted whitelist/blacklist
var stateEngine *state.Engine
if cfg.State.Enabled {
    stateEngine = state.NewEngine(cfg.State, cfg.Whitelist, logger)
    if repo != nil {
        wl, _ := repo.ListWhitelist(ctx)
        bl, _ := repo.ListBlacklist(ctx)
        stateEngine.Whitelist().LoadFromStorage(wl, bl)
    }
}

// 8. Create capture pipeline from full config and logger
pipeline, err := capture.NewPipeline(cfg, logger)
// On failure: slog.Error + os.Exit(1)

// 9. Create shutdown manager and get signal context
sm := shutdown.NewManager()
signalCtx := sm.WaitForSignal(context.Background())

// 10. Start capture pipeline (enables monitor mode, opens pcap, starts goroutines)
pipeline.Start(signalCtx)
// On failure: slog.Error + os.Exit(1)

// 11. Register cleanup hooks (capture stop, storage close)
//
// capture_stop uses context.Background() rather than the shutdown context
// because the pipeline must complete its cleanup (disable monitor mode,
// restore the interface) regardless of any shutdown deadline. The internal
// 5s timeout inside Pipeline.Stop bounds the operation, and the shutdown
// manager's overall deadline still bounds total shutdown duration.
sm.Register("capture_stop", func() error { return pipeline.Stop(context.Background()) })
if repo != nil {
    sm.Register("storage_close", func() error { return repo.Close() })
}

// 12. Create detection engine
engine := detector.NewEngine(cfg.Detection)

// 13. Wire frame consumers (fan-out when both detection + state are active)
// Detection+State: fanOut(pipeline.Frames(), detectorCh, stateCh)
// Detection only: engine.Run(signalCtx, pipeline.Frames())
// State only: consumeStateFrames(signalCtx, pipeline.Frames(), stateEngine)
// Neither: consumeFrames(signalCtx, pipeline.Frames())

// 14. Start eviction, snapshot writer, auto-learning goroutines
if stateEngine != nil { go stateEngine.RunEviction(signalCtx) }
if stateEngine != nil && repo != nil { go runSnapshotWriter(...) }
if stateEngine != nil && cfg.Whitelist.AutoLearning.Enabled { go autoLearn(...) }

// 15. Consumer stop hook, block until signal, shutdown
sm.Register("consumer_stop", func() error { consumerWG.Wait(); return nil })
<-signalCtx.Done()
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
sm.Shutdown(shutdownCtx)
```

## Data Flow Across Boundary

```
cmd/tobimaru/main.go
    │
    │  config.Load(path) ──────► *config.Config
    │  logging.New(cfg.Log) ───► *slog.Logger
    │  storage.Open(cfg.Storage) ─► storage.Repository
    │  state.NewEngine(cfg, wlCfg) ─► *state.Engine
    │  capture.NewPipeline(cfg) ───► *capture.Pipeline
    │  shutdown.NewManager() ──────► *shutdown.Manager
    │
    │  Pipeline.Start(signalCtx) ──► enables monitor mode, opens pcap
    │  Pipeline.Frames() ──────────► <-chan *parser.ParsedFrame
    │  fanOut(source, sinks...) ───► distributes frames to detector + state
    │  detector.NewEngine(cfg) ────► *detector.Engine
    │  Engine.Run(signalCtx, ch) ──► starts dispatch goroutine
    │  Engine.Alerts() ────────────► <-chan *detector.SecurityEvent
    │  state.Engine.ProcessFrame() ► updates AP/client maps per frame
    │  state.Engine.Snapshot() ────► *state.Snapshot (periodically persisted)
    │  repo.SaveEvent(event) ──────► persists security events to SQLite
    │  Manager.Shutdown(ctx) ──────► runs hooks (Pipeline.Stop, repo.Close)
    │
    ▼
*config.Config flows INTO main from internal/config
*slog.Logger flows OUT of main (set as default, used by all code)
storage.Repository lives inside main, opened early and closed at shutdown
*state.Engine lives inside main, processes frames, provides state snapshots
*capture.Pipeline lives inside main, started and stopped by main
*detector.Engine lives inside main, created and started by main
<-chan *parser.ParsedFrame flows from pipeline via fanOut to detector + state
<-chan *detector.SecurityEvent flows from engine into consumeAlerts goroutine
*shutdown.Manager lives inside main, receives hooks from components
```

Direction: `internal/*` → `cmd/tobimaru` (all imports go UP to main). `cmd/tobimaru` is the orchestrator: it creates, starts, and stops all components.

## Error Propagation

- Config loading failure → `os.Exit(1)` via `fmt.Fprintf(stderr)` — no graceful shutdown needed (nothing initialized yet)
- Storage open failure → `slog.Error` + `os.Exit(1)` — logger is available
- Pipeline creation failure → `slog.Error` + `os.Exit(1)` — logger is available, config was loaded
- Pipeline start failure → `slog.Error` + `os.Exit(1)` — monitor mode or pcap handle could not be opened
- Shutdown failure → `os.Exit(1)` after logging the error
- Individual hook failures during shutdown → aggregated via `errors.Join`, does NOT prevent other hooks from running
- Context deadline exceeded during shutdown → remaining hooks are skipped, shutdown returns immediately with error
- Storage write failures (SaveEvent, SaveSnapshot) → logged as warnings, do NOT crash the daemon
- Storage event pruning failures (PruneEvents) → logged as warnings, do NOT crash the daemon
- Whitelist/blacklist load failures at startup → logged as warnings; the engine continues with empty lists

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
