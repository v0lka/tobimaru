# Architecture: Layers

## Context

Tobimaru follows a strictly layered architecture where `cmd/` consumes `internal/` packages, and `internal/` packages may consume each other following explicit import rules. No package imports `cmd/`. No circular dependencies are allowed.

## Layer Hierarchy

```
cmd/tobimaru (entry point, orchestrator)
    │
    ├──► internal/config     (YAML loading, validation, defaults)
    │       │
    │       └── no internal imports (self-contained)
    │
    ├──► internal/logging    (slog factory)
    │       │
    │       └──► internal/config (for LogConfig type only)
    │
    ├──► internal/shutdown   (signal handling, cleanup hooks)
    │       │
    │       └── no internal imports (self-contained)
    │
    ├──► internal/version    (build metadata)
    │       │
    │       └── no internal imports (self-contained)
    │
    ├──► internal/capture    (pcap capture, monitor mode, channel hopping, pipeline)
    │       │
    │       ├──► internal/config (for Config, CaptureConfig, ChannelHoppingConfig)
    │       ├──► internal/parser (for ParsedFrame type)
    │       └──► internal/platform (for Capabilities type)
    │
    ├──► internal/detector   (detection engine, rule interface, security events)
    │       │
    │       ├──► internal/config (for DetectionConfig type)
    │       └──► internal/parser (for ParsedFrame type)
    │
    ├──► internal/state      (network state engine, AP/client maps, whitelist, auto-learning)
    │       │
    │       ├──► internal/config (for StateConfig, WhitelistConfig types)
    │       └──► internal/parser (for ParsedFrame type)
    │
    ├──► internal/storage    (persistence layer, SQLite repository)
    │       │
    │       ├──► internal/config (for StorageConfig type)
    │       ├──► internal/detector (for SecurityEvent type)
    │       └──► internal/state (for APInfo, ClientInfo, WhitelistEntry, BlacklistEntry, Snapshot types)
    │
    ├──► internal/api        (HTTP API + SSE hub + embedded SPA dashboard)
    │       │
    │       ├──► internal/config   (for APIConfig, AuthConfig, CORSConfig)
    │       ├──► internal/state    (for *Engine read access in handlers)
    │       ├──► internal/storage  (for Repository: events, sessions, lists)
    │       ├──► internal/detector (for *Engine read access + SetDedupWindow, SecurityEvent)
    │       ├──► internal/capture  (for *Pipeline.Capabilities and CurrentChannel)
    │       ├──► internal/version  (for build info on /api/status)
    │       ├──► internal/logging  (for Level/SetLevel runtime adjustments)
    │       └──► internal/api/web  (embedded SPA assets via go:embed)
    │
    ├──► internal/api/web    (embedded React+Vite dashboard bundle)
    │       │
    │       └── no internal imports (self-contained, used only by internal/api)
    │
    ├──► internal/platform   (runtime platform capabilities detection)
    │       │
    │       └── no internal imports (self-contained)
    │
    └──► internal/parser     (802.11 frame parsing and classification)
            │
            └── no internal imports (self-contained)

    └──► internal/testutil   (shared test utilities for pcap data generation)
            │
            └── no internal imports (self-contained, used only in _test.go files)
```

## Dependency Rules

- `cmd/tobimaru` is the **sole entry point** and the **only consumer** of all `internal/` packages
- `internal/` packages are **not importable** by external consumers (Go `internal` visibility)
- Cross-package dependencies within `internal/`:
  - `internal/logging` → `internal/config` (for `LogConfig` type only)
  - `internal/capture` → `internal/config` (for `Config` and capture-specific types)
  - `internal/capture` → `internal/parser` (for `ParsedFrame` type)
  - `internal/capture` → `internal/platform` (for `Capabilities` type)
  - `internal/detector` → `internal/config` (for `DetectionConfig` type)
  - `internal/detector` → `internal/parser` (for `ParsedFrame` type)
  - `internal/state` → `internal/config` (for `StateConfig`, `WhitelistConfig` types)
  - `internal/state` → `internal/parser` (for `ParsedFrame` type)
  - `internal/storage` → `internal/config` (for `StorageConfig` type)
  - `internal/storage` → `internal/detector` (for `SecurityEvent` type)
  - `internal/storage` → `internal/state` (for `APInfo`, `ClientInfo`, `WhitelistEntry`, `BlacklistEntry`, `Snapshot` types)
  - `internal/api` → `internal/{config,state,storage,detector,capture,version,logging}`
  - `internal/api` → `internal/api/web` (embedded SPA only)
- `internal/config`, `internal/shutdown`, `internal/version`, `internal/parser`, `internal/platform`, `internal/api/web`, and `internal/testutil` are self-contained with zero project imports
- No `internal/` package imports `cmd/`
- All future Phase packages (`analytics/`, etc.) follow the same rule: reside in `internal/` and are consumed by `cmd/tobimaru`

## Top-Level Directory Responsibilities

| Directory | Role |
|-----------|------|
| `cmd/tobimaru/` | Main binary entry point. Parses flags, loads config, initializes logger, wires components, handles startup and shutdown orchestration |
| `internal/` | All application logic. Not importable by packages outside this module |
| `configs/` | Sample YAML configuration files and templates |
| `docs/` | Development documentation and roadmaps |
| `.github/workflows/` | CI/CD pipeline definitions |
| `specs/` | This specification system |

## Invariants

- `cmd/tobimaru` is always the sole orchestrator of `internal/` packages
- `internal/config`, `internal/parser`, `internal/platform`, and `internal/testutil` are self-contained — they never import other `internal/` packages (provide types consumed by others)
- `internal/capture` depends on `internal/config`, `internal/parser`, and `internal/platform` — it does not depend on logging, shutdown, or version
- Circular imports are forbidden at any layer
- `internal/` packages expose only what other packages need through exported identifiers
- All `internal/` packages have corresponding test files in the same directory

## Anti-Patterns

- **Don't add `internal/` imports to `internal/config` or `internal/parser`** — they are designed as leaf packages providing types to others
- **Don't create a `pkg/` or `lib/` directory** — by convention, only `cmd/` and `internal/` exist; exported library code would live in `internal/` packages consumed by `cmd/`
- **Don't bypass `cmd/tobimaru`** — no `internal/` package should have its own `main` function or be runnable independently
- **Don't import test files from other packages** — test utilities shared across packages go into `internal/<pkg>` and are exported (used in `_test.go` via import)
