# Tobimaru WiFi Watchdog — Agent Instructions

This file provides guidance for AI coding agents working on this project.

## Project Overview

Tobimaru is a Go-based WiFi intrusion detection system (WIDS). It operates as a daemon that monitors wireless traffic, detects attacks, and provides monitoring through a REST API and an embedded React 19 web dashboard — all in a single binary.

The project follows Phases (0–12) as defined in `docs/development/wifi-watchdog-roadmap.md`. Phases 0–5 (mandatory) are complete.

## Project Status

| Phase | Status      | Description                                                                                                                                                                      |
| ----- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | ✅ Complete | Foundation (config, logging, shutdown, version, CI)                                                                                                                              |
| 1     | ✅ Complete | Capture Engine (monitor mode, pcap, channel hopping, parsing)                                                                                                                    |
| 2     | ✅ Complete | Detection Engine (rule interface, dedup, event model, and concrete rules: deauth/disassoc/beacon flood, evil twin, unauthorized device — all with unit + pcap integration tests) |
| 3     | ✅ Complete | Network State & Storage (AP/client tracking, whitelist/blacklist, SQLite persistence)                                                                                            |
| 4     | ✅ Complete | REST API & Dashboard (chi, SSE, React 19 SPA, auth with admin/user roles)                                                                                                        |
| 5     | ✅ Complete | Cross-platform (macOS support via CoreWLAN + BPF, Linux native, runtime capability detection)                                                                                    |

Two components span the entire project:

- **Web dashboard** (`web/`) — React 19 + TypeScript + Vite + Tailwind CSS SPA. Built into `internal/api/web/dist/` and embedded via `go:embed`. Pages: Status, Map (APs/clients), Events, Stats, Settings, Login.
- **Specification system** (`specs/`) — structured docs covering architecture, domains, contracts, and ADRs. See `specs/INDEX.md` for navigation.

## Language and Tooling

- **Language:** Go 1.26+
- **Module path:** `github.com/vkochetkov/tobimaru`
- **Build system:** GNU Make (`Makefile`)
- **Linter:** golangci-lint v2 (config: `.golangci.yml`)
- **CI:** GitHub Actions (`.github/workflows/ci.yml`) — lint, test, build, macOS test
- **Frontend:** Node.js + npm, React 19, TypeScript, Vite, Tailwind CSS, ESLint

## Key Dependencies

| Module                         | Purpose                                   |
| ------------------------------ | ----------------------------------------- |
| `gopkg.in/yaml.v3`             | YAML config parsing (strict, KnownFields) |
| `github.com/gopacket/gopacket` | pcap capture + 802.11 frame decoding      |
| `github.com/go-chi/chi/v5`     | HTTP router for REST API                  |
| `golang.org/x/crypto`          | bcrypt password hashing                   |
| `modernc.org/sqlite`           | Pure-Go SQLite (CGO-free)                 |

## Architecture

Tobimaru follows a strict layered architecture where `cmd/tobimaru` is the sole orchestrator and all business logic lives in `internal/` packages. No circular dependencies are allowed.

```
cmd/tobimaru (entry point, orchestrator — imports all internal/ packages)
    │
    ├──► internal/config        (self-contained: YAML loading, validation, defaults)
    ├──► internal/logging       (→ config: slog factory from LogConfig)
    ├──► internal/shutdown      (self-contained: signal handling, LIFO cleanup hooks)
    ├──► internal/version       (self-contained: build metadata via ldflags)
    ├──► internal/platform      (self-contained: runtime capability detection per OS)
    ├──► internal/parser        (self-contained: 802.11 frame parsing and classification)
    ├──► internal/capture       (→ config, parser, platform: pcap, monitor mode, channel hopping, pipeline)
    ├──► internal/detector      (→ config, parser: rule interface, engine, dedup, security events)
    ├──► internal/state         (→ config, parser: AP/client maps, whitelist/blacklist, auto-learning)
    ├──► internal/storage       (→ config, detector, state: SQLite repository for events, snapshots, sessions, lists)
    ├──► internal/api           (→ config, state, storage, detector, capture, version, logging: chi server, SSE hub, handlers)
    │       └──► internal/api/web   (self-contained: embedded React SPA via go:embed)
    └──► internal/testutil      (self-contained: shared test helpers for pcap data generation)
```

Self-contained packages have zero internal imports: `config`, `shutdown`, `version`, `platform`, `parser`, `api/web`, `testutil`.

See `specs/architecture/layers.md` for the full dependency DAG and import rules.

## Development Commands

```bash
# Full rebuild (dependencies + web + binary)
make all         # Restore all deps (Go + npm), build web, then build binary

# Go
make build       # Build for current platform (embeds web/dist)
make build-all   # Cross-compile for linux/amd64, linux/arm64, darwin/arm64
make test        # Run tests with race detector and coverage
make test-cover  # Run tests and open coverage report in browser
make lint        # Run golangci-lint
make run         # Build and run with ldflags
make clean       # Remove build artifacts (keeps committed web/dist)
make fmt         # Format all Go source
make tidy        # Tidy Go modules

# Web dashboard
make web-deps    # Install Node.js dependencies (npm ci) — prerequisite for make web
make web         # Build SPA into internal/api/web/dist/
make web-clean   # Remove embedded SPA bundle
make lint-web    # Lint SPA sources with ESLint

# Utilities
make help        # List all targets
```

> **Note:** A pre-built dashboard bundle is committed to `internal/api/web/dist/` so `make build` always produces a complete binary. Run `make web-deps && make web` only when the SPA source changes. `make web-deps` must be run before `make web` to install TypeScript and other Node dependencies.

## Running Components

### Daemon (capture + detection + state)

```bash
sudo ./bin/tobimaru -config configs/tobimaru.yaml
```

### Daemon with API + Dashboard

Enable `api.enabled: true` and `storage.enabled: true` in config, then:

```bash
sudo ./bin/tobimaru -config configs/tobimaru.yaml
# Dashboard at http://127.0.0.1:8080, API at /api/
```

### Web Dashboard in Dev Mode (hot reload)

```bash
# Terminal 1: backend
sudo ./bin/tobimaru -config configs/tobimaru.yaml

# Terminal 2: frontend
cd web && npm run dev
# Opens at http://localhost:5173, proxies /api to 127.0.0.1:8080
```

### Password Hash Generation

The `-hash-password` flag is a built-in bcrypt hash utility. Passwords are
never stored in plaintext — the YAML config accepts only pre-hashed values in
`auth.admin_password_hash` and `auth.user_password_hash`. The flag prompts
for the password interactively (without echo) so the password never appears
in the process listing or shell history. No external tools are needed.

```bash
./bin/tobimaru -hash-password
```

## Startup Sequence

The orchestrator (`cmd/tobimaru/main.go`) follows this sequence:

1. Parse CLI flags (`-config`, `-version`, `-hash-password`).
   `-hash-password` is a standalone utility — it prompts for a password
   interactively, prints a bcrypt hash, and exits. The daemon does not start
   when this flag is set.
2. Load and validate YAML configuration
3. Initialize structured logger
4. Open SQLite storage (if enabled)
5. Create state engine, load persisted whitelist/blacklist
6. Wire detection engine (fails fast if enabled but no rules registered)
7. Create capture pipeline, start with signal context
8. Register shutdown hooks (capture stop, storage close, API stop)
9. Create SSE hub (if API enabled)
10. Start consumers based on enabled features:
    - Fan-out (if both detection + state active)
    - Detection engine + alert consumer
    - State engine frame consumer
    - State eviction goroutine
    - Snapshot writer (if state + storage enabled)
    - Auto-learning (if enabled)
    - API server + SSE hub + periodic status publisher
11. Block until SIGINT/SIGTERM
12. Shutdown hooks execute in LIFO order (30s deadline)

## Configuration

The YAML config is validated with strict parsing (unknown keys cause failure). All sections have sensible defaults except `monitor.interface` which is required.

Key config sections: `log`, `monitor` (interface, capture, channel_hopping), `detection`, `state`, `whitelist`, `storage`, `api` (listen, auth, CORS, timeouts).

When `api.auth.enabled` is true, `storage.enabled` must also be true (sessions are persisted in SQLite).

## Web Dashboard

The dashboard is a React 19 SPA in `web/`:

- **Pages:** `Status.tsx`, `Map.tsx`, `Events.tsx`, `Stats.tsx`, `Settings.tsx`, `Login.tsx`
- **State:** `auth.tsx` (AuthContext), `api.ts` (REST client), `sse.ts` (SSE connection)
- **Styling:** Tailwind CSS via `tailwind.config.ts`
- **Charts:** Recharts (`recharts` package)
- **Config YAML display:** `js-yaml` for formatting config in settings page

The build output goes to `internal/api/web/dist/` and is embedded at compile time. The SPA is served for all non-`/api/` routes via chi's `NotFound` handler.

## Security Policy

This project maintains a security policy in [SECURITY.md](./SECURITY.md).
All AI coding agents MUST read and follow SECURITY.md before making changes.
It contains:

- Threat model and trust boundaries
- Secure coding guidelines specific to this project's stack
- Hard constraints and forbidden patterns for AI agents
- Vulnerability reporting procedures

Any code contribution that violates the rules in SECURITY.md will be rejected.

## Specifications

Detailed system specs live in `specs/`. Before making structural changes, read the relevant spec:

- Start with `specs/INDEX.md` to find the right document for your task.
- `specs/META.md` defines spec formats and update rules.
- `specs/WORKFLOW.md` explains how to use and update the spec system.
- `specs/architecture/layers.md` defines the import DAG and anti-patterns.

Current ADRs: 001-yaml-config, 002-ldflags-version, 003-slog-logging, 004-sqlite-pure-go, 005-chi-spa-sse.
