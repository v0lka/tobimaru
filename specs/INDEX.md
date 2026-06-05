# Specification Index

Navigation hub for the Tobimaru specification system. Find the right spec for your task.

## Task → Spec Map

| Task | Spec(s) to Read |
|------|----------------|
| Understand the project architecture | [Architecture: Layers](architecture/layers.md) |
| Add a new config field or section | [Configuration](domains/configuration.md), [Contract: Config → Logging](contracts/config-logging.md) |
| Change log output format or add log destinations | [Logging](domains/logging.md), [ADR-003](decisions/003-slog-logging.md) |
| Add a new component with cleanup needs | [Lifecycle](domains/lifecycle.md), [Contract: Main ↔ Internal](contracts/main-internal.md) |
| Add a new internal package | [Architecture: Layers](architecture/layers.md), [Contract: Main ↔ Internal](contracts/main-internal.md) |
| Change how main.go wires components | [Contract: Main ↔ Internal](contracts/main-internal.md), [Lifecycle](domains/lifecycle.md) |
| Work on frame capture or channel hopping | [Capture Engine](domains/capture.md), [Configuration](domains/configuration.md), [Contract: Main ↔ Internal](contracts/main-internal.md) |
| Add support for a new platform (macOS, BSD, etc.) | [Capture Engine](domains/capture.md), [Architecture: Layers](architecture/layers.md), [Build & Versioning](domains/build-and-versioning.md) |
| Query platform capabilities at runtime | [Capture Engine](domains/capture.md), [Contract: Main ↔ Internal](contracts/main-internal.md) |
| Add or modify 802.11 frame parsing | [Frame Parser](domains/parser.md), [Capture Engine](domains/capture.md) |
| Work on detection engine / attack rules | [Detection Engine](domains/detection.md), [Configuration](domains/configuration.md), [Contract: Main ↔ Internal](contracts/main-internal.md) |
| Add or modify security event types or severity | [Detection Engine](domains/detection.md) |
| Work on network state engine (AP/client tracking) | [Architecture: Layers](architecture/layers.md), [Configuration](domains/configuration.md), [Contract: Main ↔ Internal](contracts/main-internal.md) |
| Work on storage/persistence (SQLite, snapshots) | [Architecture: Layers](architecture/layers.md), [Configuration](domains/configuration.md), [Contract: Main ↔ Internal](contracts/main-internal.md) |
| Work on whitelist/blacklist or auto-learning | [Architecture: Layers](architecture/layers.md), [Configuration](domains/configuration.md) |
| Modify the CI pipeline or Makefile | [Build & Versioning](domains/build-and-versioning.md) |
| Change build flags or add a target platform | [Build & Versioning](domains/build-and-versioning.md), [ADR-002](decisions/002-ldflags-version.md) |
| Add shutdown cleanup for a component | [Lifecycle](domains/lifecycle.md) |
| Understand why a technology choice was made | `decisions/` directory (search by topic) |
| Add a new spec or ADR | [META.md](META.md) |
| Learn how to use the spec system | [WORKFLOW.md](WORKFLOW.md) |

## Dependency Graph

```
cmd/tobimaru (entry point, orchestrator)
    │
    ├──► internal/config        [self-contained, provides types]
    │       │
    │       ├──► LogConfig type consumed by internal/logging
    │       ├──► Config, CaptureConfig, ChannelHoppingConfig consumed by internal/capture
    │       ├──► DetectionConfig type consumed by internal/detector
    │       ├──► StateConfig, WhitelistConfig consumed by internal/state
    │       └──► StorageConfig consumed by internal/storage
    │
    ├──► internal/logging       [depends on internal/config]
    │
    ├──► internal/shutdown      [self-contained]
    │
    ├──► internal/version       [self-contained, ldflags-injected]
    │
    ├──► internal/capture       [depends on internal/config, internal/parser, internal/platform]
    │       │
    │       ├──► internal/config     (for Config and capture types)
    │       ├──► internal/parser     (for ParsedFrame)
    │       └──► internal/platform   (for Capabilities)
    │
    ├──► internal/detector      [depends on internal/config, internal/parser]
    │       │
    │       ├──► internal/config     (for DetectionConfig)
    │       └──► internal/parser     (for ParsedFrame)
    │
    ├──► internal/state         [depends on internal/config, internal/parser]
    │       │
    │       ├──► internal/config     (for StateConfig, WhitelistConfig)
    │       └──► internal/parser     (for ParsedFrame)
    │
    ├──► internal/storage       [depends on internal/config, internal/detector, internal/state]
    │       │
    │       ├──► internal/config     (for StorageConfig)
    │       ├──► internal/detector   (for SecurityEvent)
    │       └──► internal/state      (for APInfo, ClientInfo, etc.)
    │
    ├──► internal/platform      [self-contained, no project imports]
    │
    └──► internal/parser        [self-contained, no project imports]
```

## Directory Listing

### System Files
- [META.md](META.md) — spec system rules, templates, and update protocol
- [WORKFLOW.md](WORKFLOW.md) — developer and AI agent usage guide
- [INDEX.md](INDEX.md) — this file

### Architecture
- [layers.md](architecture/layers.md) — package hierarchy, import rules, anti-patterns

### Domains
- [configuration.md](domains/configuration.md) — YAML config loading, validation, defaults
- [logging.md](domains/logging.md) — slog factory from LogConfig
- [lifecycle.md](domains/lifecycle.md) — graceful shutdown via signals and hooks
- [build-and-versioning.md](domains/build-and-versioning.md) — ldflags, Makefile, CI pipeline
- [capture.md](domains/capture.md) — pcap capture, monitor mode, channel hopping, pipeline
- [detection.md](domains/detection.md) — detection engine, rule interface, security events
- [state.md](domains/state.md) — network state engine, AP/client maps, whitelist, auto-learning
- [storage.md](domains/storage.md) — SQLite persistence, repository pattern, snapshots
- [parser.md](domains/parser.md) — 802.11 frame parsing and classification

### Contracts
- [config-logging.md](contracts/config-logging.md) — `LogConfig` → `logging.New()` boundary
- [main-internal.md](contracts/main-internal.md) — `cmd/tobimaru` wiring of all internal packages

### Decisions
- [_template.md](decisions/_template.md) — ADR template
- [001-yaml-config.md](decisions/001-yaml-config.md) — YAML with KnownFields strict parsing
- [002-ldflags-version.md](decisions/002-ldflags-version.md) — ldflags injection for versioning
- [003-slog-logging.md](decisions/003-slog-logging.md) — `log/slog` over zap, zerolog, logrus
- [004-sqlite-pure-go.md](decisions/004-sqlite-pure-go.md) — `modernc.org/sqlite` for CGO-free persistence
