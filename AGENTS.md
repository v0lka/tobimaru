# Tobimaru WiFi Watchdog — Agent Instructions

This file provides guidance for AI coding agents working on this project.

## Project Overview

Tobimaru is a Go-based WiFi intrusion detection system (WIDS). It operates as a daemon that monitors wireless traffic, detects attacks, and provides monitoring through a REST API and web dashboard.

The project is structured in Phases (0-12) as defined in `docs/development/wifi-watchdog-roadmap.md`. Phase 0 (Foundation) is complete.

## Language and Tooling

- **Language:** Go 1.22+
- **Module path:** `github.com/vkochetkov/tobimaru`
- **Build system:** GNU Make (`Makefile`)
- **Linter:** golangci-lint v2 (config: `.golangci.yml`)
- **CI:** GitHub Actions (`.github/workflows/ci.yml`)

## Architecture

Tobimaru follows a strict layered architecture:
- `cmd/tobimaru/` — entry point, orchestrator
- `internal/config/` — configuration (YAML loading, validation, defaults)
- `internal/logging/` — structured logging (slog)
- `internal/shutdown/` — graceful shutdown (signals, cleanup hooks)
- `internal/version/` — build metadata (ldflags injection)

See `specs/architecture/layers.md` for the full dependency DAG and import rules.

## Development Commands

```bash
make build       # Build for current platform
make build-all   # Cross-compile for all targets
make test        # Run tests with race detector
make lint        # Run golangci-lint
make run         # Build and run
make clean       # Remove build artifacts
make fmt         # Format all Go source
make tidy        # Tidy Go modules
```

## Specifications

Detailed system specs live in `specs/`. Before making structural changes, read the relevant spec:

- Start with `specs/INDEX.md` to find the right document for your task.
- `specs/META.md` defines spec formats and update rules.
- `specs/WORKFLOW.md` explains how to use and update the spec system.
