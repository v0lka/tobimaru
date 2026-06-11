# Developer Guide

This guide covers the architecture, development workflow, and contribution
process for Tobimaru.

## Architecture

Tobimaru follows a strict layered architecture where `cmd/tobimaru` is the
sole orchestrator and all business logic lives in `internal/` packages.

### Package Dependency Graph

```
cmd/tobimaru (orchestrator — imports all internal packages)
    │
    ├── internal/config        (self-contained: YAML loading, validation, defaults)
    ├── internal/logging       (→ config: slog factory)
    ├── internal/shutdown      (self-contained: signal handling, LIFO cleanup hooks)
    ├── internal/version       (self-contained: ldflags-injected build metadata)
    ├── internal/platform      (self-contained: runtime capability detection per OS)
    ├── internal/parser        (self-contained: 802.11 frame parsing)
    ├── internal/capture       (→ config, parser, platform: pcap, monitor mode, channel hopping)
    ├── internal/detector      (→ config, parser: rule interface, engine, dedup, security events)
    ├── internal/state         (→ config, parser: AP/client maps, whitelist/blacklist, learning)
    ├── internal/storage       (→ config, detector, state: SQLite events, snapshots, sessions, lists)
    ├── internal/api           (→ config, state, storage, detector, capture, version, logging)
    │       └── internal/api/web (self-contained: embedded React SPA via go:embed)
    └── internal/testutil      (self-contained: pcap data generation helpers)
```

### Import Rules

- `cmd/tobimaru` is the ONLY consumer of `internal/` packages.
- No `internal/` package imports `cmd/`.
- Circular dependencies are forbidden.
- Self-contained packages with zero project imports: `config`, `shutdown`,
  `version`, `platform`, `parser`, `api/web`, `testutil`.

See `specs/architecture/layers.md` for the full dependency DAG and import
rules.

### Directory Layout

```
cmd/tobimaru/          Entry point, wiring, orchestration
internal/
  config/              YAML loading, validation, defaults
  logging/             slog logger factory
  shutdown/            Signal handling, LIFO cleanup hooks
  version/             Build metadata (injected at compile time)
  platform/            Runtime capability detection (Linux/macOS/other)
  parser/              802.11 frame parsing and classification
  capture/             Monitor mode, pcap handle, channel hopping, pipeline
  detector/            Detection engine, rules, security events
  state/               AP/client tracking, whitelist/blacklist, auto-learning
  storage/             SQLite repository (events, snapshots, sessions, lists)
  api/                 chi router, REST handlers, SSE hub, auth
    web/               Embedded React 19 SPA (go:embed dist/)
  testutil/            Test helpers (pcap generation)
configs/               Sample configuration files
web/                   React 19 + Vite + TypeScript SPA sources
specs/                 System specifications
  architecture/        Package hierarchy and rules
  domains/             Conceptual domain specs
  contracts/           Cross-boundary interface specs
  decisions/           Architecture Decision Records (ADRs)
docs/                  Documentation
  development/         Roadmap and internal development notes
```

## Development Setup

### Prerequisites

- Go 1.26+
- GNU Make
- golangci-lint v2 (for linting; the Makefile invokes `golangci-lint-v2`)
- Node.js 22+ and npm (only when modifying the web dashboard)

### Getting Started

```bash
git clone https://github.com/vkochetkov/tobimaru.git
cd tobimaru
make tidy
make build
make test
make lint
```

A pre-built dashboard bundle is committed to `internal/api/web/dist/` so the
backend always builds without Node. Run `make web-deps && make web` only when
SPA sources change. `make web-deps` must be run before `make web` to install
TypeScript and other Node dependencies.

## Make Targets

| Target | Description |
|--------|-------------|
| `make all` | Restore all deps (Go + npm), build web, then build binary |
| `make build` | Build for current platform → `bin/tobimaru` (embeds `web/dist`) |
| `make build-all` | Cross-compile for `linux/amd64`, `linux/arm64`, `darwin/arm64` |
| `make test` | Run tests with race detector and coverage |
| `make test-cover` | Run tests and open the coverage report |
| `make lint` | Run `golangci-lint run ./...` |
| `make run` | `go run` with ldflags |
| `make clean` | Remove `bin/` and `coverage.out` (keeps committed `web/dist`) |
| `make fmt` | `go fmt ./...` |
| `make tidy` | `go mod tidy` |
| `make web-deps` | `npm ci` inside `web/` |
| `make web` | Build the SPA into `internal/api/web/dist/` |
| `make web-clean` | Remove the embedded SPA bundle |
| `make lint-web` | Run ESLint on the SPA sources |
| `make help` | List all targets |

## Build System

Version metadata is injected at compile time via ldflags:

```bash
# Variables set automatically by Makefile:
VERSION  # git tag or "dev"
COMMIT   # git rev-parse --short HEAD
DATE     # UTC ISO 8601 timestamp

# Injected into internal/version package:
-X github.com/vkochetkov/tobimaru/internal/version.Version=$(VERSION)
-X github.com/vkochetkov/tobimaru/internal/version.Commit=$(COMMIT)
-X github.com/vkochetkov/tobimaru/internal/version.Date=$(DATE)
```

Binaries are stripped (`-s -w`) for smaller output.

## Testing

Run all tests with the race detector:

```bash
make test
```

Key testing practices:

- Tests use the standard `testing` package.
- Race detector is enabled by default (`-race` flag).
- On macOS the Makefile sets `CGO_LDFLAGS=-Wl,-no_warn_duplicate_libraries`
  to silence the duplicate-library warning emitted on Apple Silicon.
- `internal/testutil/` provides helpers for generating synthetic pcap data.
- CI runs tests on both Ubuntu and macOS.

### Writing Tests

- Place test files adjacent to the code they test (`foo_test.go` next to
  `foo.go`).
- Use table-driven tests where applicable.
- Test both success and error paths.
- For capture/parser/detector tests, use `testutil.BuildBeaconPcap()`,
  `testutil.BuildDeauthPcap()`, `testutil.BuildDeauthFloodPcap()`,
  `testutil.BuildDisassocFloodPcap()`, `testutil.BuildProbeReqPcap()`,
  `testutil.BuildProbeRespPcap()` and friends to create synthetic frames.

## Linting

The project uses golangci-lint v2 with strict configuration (`.golangci.yml`):

```bash
make lint
```

CI enforces linting on all PRs. Fix all lint issues before submitting changes.

## CI Pipeline

GitHub Actions (`.github/workflows/ci.yml`) runs on push/PR to `main`:

1. **Lint** — `golangci-lint v2` on `ubuntu-latest` (Go 1.26).
2. **Web** — Vite build + ESLint on Node 22; uploads `internal/api/web/dist`
   as an artifact.
3. **Test** — `go test -race -cover` on `ubuntu-latest`.
4. **Build** — matrix cross-compile for `linux/amd64`,
   `linux/arm64` (`ubuntu-24.04-arm`) and `darwin/arm64` (`macos-latest`).
5. **Test (macOS)** — tests and a `--version` smoke test on `macos-latest`.

All jobs must pass before merge.

## Data Flow

### Startup Sequence

1. Parse CLI flags (`-config`, `-version`, `-hash-password`).
   The `-hash-password` flag is a standalone utility: it generates a bcrypt
   hash, prints it to stdout, and exits immediately — the daemon never
   starts. This is how operators produce the `admin_password_hash`/
   `user_password_hash` values for the YAML config.
2. Load and validate YAML configuration.
3. Initialize structured logger.
4. Open SQLite storage (when `storage.enabled`).
5. Create the state engine and load persisted whitelist/blacklist.
6. Create the detection engine and register configured rules.
7. Create the capture pipeline; start it with the signal context (enables
   monitor mode, opens pcap, starts the channel hopper).
8. Register shutdown hooks (`capture_stop`, `storage_close`, `api_stop`,
   `consumer_stop`).
9. Create the SSE hub when `api.enabled` is true.
10. Start consumer goroutines based on enabled features:
    - `fan-out` when both detection and state are enabled.
    - Detection engine + alert consumer (logs, persists, broadcasts via SSE).
    - State frame consumer + state eviction goroutine.
    - Snapshot writer when state and storage are both enabled.
    - Auto-learning when configured.
11. Start the API server, SSE hub `Run` loop, and a periodic status publisher.
12. Block until SIGINT/SIGTERM.
13. Execute cleanup hooks in LIFO order with a 30-second deadline.

### Frame Processing Pipeline

```
WiFi Adapter (monitor mode)
    ↓
pcap Handle (RFMon + BPF filter: mgt/ctl/data)
    ↓
Capture Loop goroutine
    ├── Read raw packet
    ├── parser.Parse() → ParsedFrame
    └── Send on frames channel (buffered, capacity = monitor.capture.frame_buffer_size)
         ↓
fanOut (when detection + state are both enabled)
    ├──► detection channel ──► Detection Engine
    │                              ├── Dispatch frame to all registered rules
    │                              ├── Rule.Process(frame) → []*SecurityEvent
    │                              ├── Deduplicate (key: eventType:srcMAC:bssid)
    │                              └── Emit on alerts channel (cap = detection.alert_buffer_size)
    │                                       ↓
    │                                  Alert Consumer goroutine
    │                                       ├── Log by severity
    │                                       ├── Persist to SQLite (if storage.enabled)
    │                                       └── Broadcast via SSE Hub (if api.enabled)
    └──► state channel ──► State Engine
                                ├── Update AP / client maps
                                └── Eviction goroutine prunes stale entries
```

When only one of detection/state is enabled, the corresponding consumer
reads directly from the capture pipeline instead of going through `fanOut`.

## Key Interfaces

### Detection Rules

New detection rules implement the `Rule` interface (`internal/detector/rule.go`):

```go
type Rule interface {
    Name() string
    Init(cfg config.DetectionConfig) error
    Process(frame *parser.ParsedFrame) []*SecurityEvent
}
```

Contracts:

- `Name()` must return a unique identifier.
- `Init()` is called once during engine setup.
- `Process()` must be a pure function — no retained frame references, no
  blocking, no panics. The engine recovers from rule panics and continues.
- Register rules before calling `engine.Run()`.

The detector package ships five concrete rules:
`DeauthFloodRule`, `DisassocFloodRule`, `BeaconFloodRule`, `EvilTwinRule`,
`UnauthorizedDeviceRule`. The flood rules share an internal `floodRule`
helper (`internal/detector/rule_flood.go`); use it when adding new flood-style
rules instead of duplicating sliding-window logic. See
[`docs/development/detection-rule-guide.md`](development/detection-rule-guide.md)
for a full walk-through.

### Security Events

Events carry detection results (`internal/detector/event.go`):

```go
type SecurityEvent struct {
    Timestamp   time.Time
    EventType   string
    Severity    Severity            // SeverityInfo, SeverityWarning, SeverityCritical
    SrcMAC      net.HardwareAddr
    DstMAC      net.HardwareAddr
    BSSID       net.HardwareAddr
    SSID        string
    Channel     int
    RSSI        int
    FrameCount  int
    Duration    time.Duration
    Metadata    map[string]any
    Description string
}
```

Use `detector.NewEvent(timestamp, eventType, severity)` to obtain a value
with `Metadata` pre-allocated.

### Platform Capabilities

Platform-specific behavior is abstracted via build tags:

- `internal/platform/capabilities_linux.go` (build tag: `linux`)
- `internal/platform/capabilities_darwin.go` (build tag: `darwin`)
- `internal/platform/capabilities_others.go` (build tag: `!linux && !darwin`)
- `internal/capture/monitor_linux.go` / `monitor_darwin.go` /
  `monitor_unsupported.go` (the macOS implementation includes a CoreWLAN
  bridge in `monitor_darwin.m`).

When adding platform-specific code, follow this pattern with appropriate
build constraints.

## Web Dashboard

The dashboard is a React 19 SPA in `web/`:

- **Pages:** `Status.tsx`, `Map.tsx`, `Events.tsx`, `Stats.tsx`,
  `Settings.tsx`, `Login.tsx`.
- **State plumbing:** `auth.tsx` (`AuthContext`), `api.ts` (REST client),
  `sse.ts` (SSE hook).
- **Styling:** Tailwind CSS via `tailwind.config.ts`.
- **Charts:** `recharts`.
- **Config display:** `js-yaml` for formatting YAML in the settings page.

The build output goes to `internal/api/web/dist/` and is embedded at compile
time via `internal/api/web/embed.go`. The SPA is served for all non-`/api/`
routes via chi's `NotFound` handler.

For dev mode with hot reload, run the daemon with `api.enabled: true` and
start `npm run dev` inside `web/`. Vite proxies `/api` to `127.0.0.1:8080`.

## Specification System

Before making structural changes, consult the specification system:

1. Start at [`specs/INDEX.md`](../specs/INDEX.md) — maps tasks to relevant
   specs.
2. Read [`specs/WORKFLOW.md`](../specs/WORKFLOW.md) — explains how to use
   and update specs.
3. Check [`specs/META.md`](../specs/META.md) — defines spec formats.

### Spec Types

| Type | Location | Purpose |
|------|----------|---------|
| Domain specs | `specs/domains/` | Conceptual domain definitions |
| Contract specs | `specs/contracts/` | Cross-boundary interfaces |
| Architecture specs | `specs/architecture/` | System-level rules (import DAG) |
| ADRs | `specs/decisions/` | Architecture Decision Records |

When adding new packages or changing interfaces, update the relevant specs.

## Architecture Decision Records

Significant design choices are documented as ADRs in `specs/decisions/`:

- **ADR-001:** YAML configuration with `KnownFields(true)` (strict parsing).
- **ADR-002:** ldflags version injection.
- **ADR-003:** slog structured logging.
- **ADR-004:** Pure-Go SQLite (`modernc.org/sqlite`, no CGO).
- **ADR-005:** chi router + embedded React SPA + SSE for real-time updates.

Use `specs/decisions/_template.md` when adding new ADRs.

## Configuration Design

The configuration system (`internal/config/`) follows these principles:

- YAML with strict parsing — unknown keys cause load failure.
- Defaults applied to zero-valued fields after decoding (`defaults.go`).
- Validation collects all errors (not fail-fast) via `errors.Join`.
- Only `monitor.interface` is truly required; everything else has defaults.
- Sentinel errors for specific validation failures.

`Config` covers `Log`, `Monitor`, `Detection`, `State`, `Whitelist`,
`Storage` and `API` sections. See [USERGUIDE.md](USERGUIDE.md#configuration)
for the full field reference.

## Adding New Packages

When creating a new `internal/` package:

1. Check `specs/architecture/layers.md` for allowed dependencies.
2. Ensure no circular imports.
3. Only `cmd/tobimaru` should import the new package.
4. Add appropriate tests.
5. Update specs if the package introduces new domain concepts or contracts.

## Development Roadmap

The project follows a phased development plan:

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | Complete | Foundation (config, logging, shutdown, version, CI) |
| 1 | Complete | Capture Engine (monitor mode, pcap, channel hopping, parsing) |
| 2 | Complete | Detection Engine (rule interface, engine, five concrete rules, pcap integration tests) |
| 3 | Complete | Network State & Storage (AP/client tracking, whitelist/blacklist, SQLite persistence) |
| 4 | Complete | REST API & Dashboard (chi, SSE, React 19 SPA, auth) |
| 5 | Complete | Cross-platform (macOS via airport-free CoreWLAN bridge + BPF) |
| 6+ | Planned | EAPOL, active countermeasures, internal monitoring, behavioural analytics, OpenWrt, advanced detection, additional integrations |

See [`docs/development/wifi-watchdog-roadmap.md`](development/wifi-watchdog-roadmap.md)
for full task breakdowns.

## External Dependencies

| Module | Purpose |
|--------|---------|
| `gopkg.in/yaml.v3` | YAML configuration parsing (strict, `KnownFields`) |
| `github.com/gopacket/gopacket` | pcap capture and 802.11 frame decoding |
| `github.com/go-chi/chi/v5` | HTTP router for the REST API |
| `golang.org/x/crypto` | bcrypt password hashing |
| `modernc.org/sqlite` | Pure-Go SQLite driver (CGO-free) |

Dependencies are minimal by design. New dependencies should be justified and
discussed in an ADR.
