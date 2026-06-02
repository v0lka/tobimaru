# Tobimaru

Tobimaru is a WiFi Intrusion Detection System (WIDS) for Linux and macOS. It operates as a daemon that monitors wireless traffic in monitor mode, detects attacks such as deauthentication floods, and provides alerting through structured logging.

## Features

- **Passive WiFi monitoring** — captures management, control, and data frames via monitor mode
- **802.11 frame parsing** — extracts MAC addresses, SSIDs, channels, RSSI, reason codes, and information elements
- **Channel hopping** — scans 2.4 GHz (and optionally 5 GHz) bands with weighted dwell time for primary channels
- **Detection engine** — rule-based architecture with deduplication and severity levels
- **Platform-aware** — adapts to Linux (`iw`) and macOS (`airport`) tooling with capability detection
- **Structured logging** — slog-based output in text or JSON format
- **Graceful shutdown** — SIGINT/SIGTERM handling with LIFO cleanup hooks
- **Cross-compilation** — builds for linux/amd64, linux/arm64, darwin/arm64

## Requirements

- Go 1.26+
- Linux or macOS
- Root/sudo access (required for monitor mode and BPF device access)
- `iw` and `ip` utilities (Linux)
- `airport` utility (macOS) — see [User Guide](docs/USERGUIDE.md) for setup

## Quick Start

```bash
# Build
make build

# Copy and edit configuration
cp configs/tobimaru.yaml tobimaru.yaml
# Set monitor.interface to your WiFi interface (e.g., wlan0 or en0)

# Run (requires root)
sudo ./bin/tobimaru -config tobimaru.yaml
```

## Configuration

Tobimaru uses a YAML configuration file. See [`configs/tobimaru.yaml`](configs/tobimaru.yaml) for a fully annotated example.

Key settings:

| Section | Field | Description |
|---------|-------|-------------|
| `log.level` | `debug`, `info`, `warn`, `error` | Log verbosity |
| `log.format` | `text`, `json` | Output format |
| `monitor.interface` | e.g. `wlan0` | WiFi interface (required) |
| `monitor.capture.snaplen` | bytes | Max bytes per frame (default: 65535) |
| `monitor.channel_hopping.enabled` | bool | Enable channel scanning |
| `monitor.channel_hopping.dwell` | duration | Time per channel (default: 300ms) |
| `detection.enabled` | bool | Enable detection engine |
| `detection.dedup_window` | duration | Suppress duplicate alerts (default: 30s) |

## Documentation

- [User Guide](docs/USERGUIDE.md) — installation, configuration, and operation
- [Developer Guide](docs/DEVELOPERGUIDE.md) — architecture, building, testing, and contributing

## Build Targets

```bash
make build       # Build for current platform
make build-all   # Cross-compile for all targets
make test        # Run tests with race detector
make lint        # Run golangci-lint
make clean       # Remove build artifacts
```

## Project Status

Tobimaru is under active development. Phases 0 (Foundation) and 1 (Capture Engine) are complete. The detection engine framework (Phase 2) is in progress — rule interface and deduplication are implemented; specific detection rules are upcoming.

See [`docs/development/wifi-watchdog-roadmap.md`](docs/development/wifi-watchdog-roadmap.md) for the full roadmap.

## License

MIT License. See [LICENSE](LICENSE) for details.
