# Developer Guide

This guide covers the architecture, development workflow, and contribution process for Tobimaru.

## Architecture

Tobimaru follows a strict layered architecture where `cmd/tobimaru` is the sole orchestrator and all business logic lives in `internal/` packages.

### Package Dependency Graph

```
cmd/tobimaru (orchestrator — imports everything)
    │
    ├── internal/config      (self-contained, no project imports)
    ├── internal/logging     (imports: config)
    ├── internal/shutdown    (self-contained)
    ├── internal/version     (self-contained, populated via ldflags)
    ├── internal/platform    (self-contained)
    ├── internal/parser      (self-contained)
    ├── internal/capture     (imports: config, parser, platform)
    └── internal/detector    (imports: config, parser)
```

### Import Rules

- `cmd/tobimaru` is the ONLY consumer of `internal/` packages
- No `internal/` package imports `cmd/`
- Circular dependencies are forbidden
- Leaf packages (`config`, `shutdown`, `version`, `parser`, `platform`) have zero project imports

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
  detector/            Detection engine, rule interface, security events
  testutil/            Test helpers (pcap generation)
configs/               Sample configuration files
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

- Go 1.22+
- GNU Make
- golangci-lint v2 (for linting)

### Getting Started

```bash
git clone https://github.com/vkochetkov/tobimaru.git
cd tobimaru
make tidy
make build
make test
make lint
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build for current platform → `bin/tobimaru` |
| `make build-all` | Cross-compile for linux/amd64, linux/arm64, darwin/arm64 |
| `make test` | Run tests with race detector and coverage |
| `make test-cover` | Run tests and open coverage report in browser |
| `make lint` | Run golangci-lint |
| `make run` | Build and run with ldflags |
| `make clean` | Remove `bin/` directory |
| `make fmt` | Format all Go source files |
| `make tidy` | Run `go mod tidy` |
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
- Tests use the standard `testing` package
- Race detector is enabled by default (`-race` flag)
- `internal/testutil/` provides helpers for generating synthetic pcap data
- CI runs tests on both Ubuntu and macOS

### Writing Tests

- Place test files adjacent to the code they test (`foo_test.go` next to `foo.go`)
- Use table-driven tests where applicable
- Test both success and error paths
- For capture/parser tests, use `testutil.GeneratePcap()` to create synthetic frames

## Linting

The project uses golangci-lint v2 with strict configuration (`.golangci.yml`):

```bash
make lint
```

CI enforces linting on all PRs. Fix all lint issues before submitting changes.

## CI Pipeline

GitHub Actions (`.github/workflows/ci.yml`) runs on push/PR to `main`:

1. **Lint** — golangci-lint on ubuntu-latest
2. **Test** — `go test -race -cover` on ubuntu-latest
3. **Build** — cross-compile for all 4 platform targets
4. **Test (macOS)** — tests and smoke test on macos-latest

All jobs must pass before merge.

## Data Flow

### Startup Sequence

1. Parse CLI flags (`-config`, `-version`)
2. Load and validate YAML configuration
3. Initialize structured logger
4. Detect platform capabilities
5. Create capture pipeline
6. Set up shutdown manager (SIGINT, SIGTERM)
7. Start pipeline (enable monitor mode, open pcap, start channel hopper)
8. Register cleanup hook (pipeline.Stop — restores interface)
9. Start detection engine (if enabled)
10. Block until signal received
11. Execute cleanup hooks in LIFO order (30s deadline)

### Frame Processing Pipeline

```
WiFi Adapter (monitor mode)
    ↓
pcap Handle (RFMon + BPF filter: mgt/ctl/data)
    ↓
Capture Loop goroutine
    ├── Read raw packet
    ├── parser.Parse() → ParsedFrame
    └── Send on frames channel (buffered, cap=1024)
         ↓
Detection Engine goroutine
    ├── Dispatch frame to all registered Rules
    ├── Rule.Process(frame) → []*SecurityEvent
    ├── Deduplicate (key: eventType:srcMAC:bssid)
    └── Emit on alerts channel (buffered, cap=256)
         ↓
Alert Consumer goroutine
    └── Log events by severity level
```

## Key Interfaces

### Detection Rules

New detection rules implement the `Rule` interface (`internal/detector/rule.go`):

```go
type Rule interface {
    Name() string
    Init(cfg DetectionConfig) error
    Process(frame *parser.ParsedFrame) []*SecurityEvent
}
```

Contracts:
- `Name()` must return a unique identifier
- `Init()` is called once during engine setup
- `Process()` must be a pure function — no retained frame references, no blocking, no panics
- Register rules before calling `engine.Run()`

### Security Events

Events carry detection results (`internal/detector/event.go`):

```go
type SecurityEvent struct {
    Timestamp   time.Time
    EventType   string
    Severity    Severity  // Info, Warning, Critical
    SrcMAC      net.HardwareAddr
    DstMAC      net.HardwareAddr
    BSSID       net.HardwareAddr
    SSID        string
    Channel     int
    RSSI        int8
    FrameCount  int
    Duration    time.Duration
    Metadata    map[string]any
    Description string
}
```

### Platform Capabilities

Platform-specific behavior is abstracted via build tags:
- `internal/platform/capabilities_linux.go` (build tag: `linux`)
- `internal/platform/capabilities_darwin.go` (build tag: `darwin`)
- `internal/platform/capabilities_others.go` (build tag: `!linux && !darwin`)
- `internal/capture/monitor_linux.go` / `monitor_darwin.go` / `monitor_unsupported.go`

When adding platform-specific code, follow this pattern with appropriate build constraints.

## Specification System

Before making structural changes, consult the specification system:

1. Start at [`specs/INDEX.md`](../specs/INDEX.md) — maps tasks to relevant specs
2. Read [`specs/WORKFLOW.md`](../specs/WORKFLOW.md) — explains how to use and update specs
3. Check [`specs/META.md`](../specs/META.md) — defines spec formats

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

- **ADR-001:** YAML configuration with `KnownFields(true)` (strict parsing)
- **ADR-002:** ldflags version injection
- **ADR-003:** slog structured logging

Use `specs/decisions/_template.md` when adding new ADRs.

## Configuration Design

The configuration system (`internal/config/`) follows these principles:

- YAML with strict parsing — unknown keys cause load failure
- Defaults applied to zero-valued fields after decoding
- Validation collects all errors (not fail-fast) via `errors.Join`
- Only `monitor.interface` is truly required; everything else has defaults
- Sentinel errors for specific validation failures

## Adding New Packages

When creating a new `internal/` package:

1. Check `specs/architecture/layers.md` for allowed dependencies
2. Ensure no circular imports
3. Only `cmd/tobimaru` should import the new package
4. Add appropriate tests
5. Update specs if the package introduces new domain concepts or contracts

## Development Roadmap

The project follows a phased development plan:

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | Complete | Foundation (config, logging, shutdown, version, CI) |
| 1 | Complete | Capture Engine (monitor mode, pcap, channel hopping, parsing) |
| 2 | In Progress | Detection Engine (rule framework done; specific rules upcoming) |
| 3+ | Planned | State/Storage, REST API, Dashboard, advanced features |

See [`docs/development/wifi-watchdog-roadmap.md`](development/wifi-watchdog-roadmap.md) for full details.

## External Dependencies

| Module | Version | Purpose |
|--------|---------|---------|
| `gopkg.in/yaml.v3` | v3.0.1 | YAML configuration parsing |
| `github.com/gopacket/gopacket` | v1.6.0 | Packet capture and 802.11 frame decoding |

Dependencies are minimal by design. New dependencies should be justified and discussed.
