# User Guide

This guide covers installing, configuring, and running Tobimaru on Linux and macOS.

## Installation

### Building from Source

Requirements:
- Go 1.22 or later
- GNU Make

```bash
git clone https://github.com/vkochetkov/tobimaru.git
cd tobimaru
make build
```

The binary is placed in `bin/tobimaru`.

### Cross-Compilation

Build binaries for all supported platforms:

```bash
make build-all
```

This produces:
- `bin/tobimaru-linux-amd64`
- `bin/tobimaru-linux-arm64`
- `bin/tobimaru-darwin-arm64`

## Platform Setup

### Linux

1. Identify your WiFi interface:

   ```bash
   iw dev
   ```

   Common names: `wlan0`, `wlp2s0`, `wlan1` (external adapter).

2. Ensure `iw` and `ip` utilities are installed:

   ```bash
   # Debian/Ubuntu
   sudo apt install iw iproute2

   # Fedora/RHEL
   sudo dnf install iw iproute
   ```

3. Run as root (required for monitor mode):

   ```bash
   sudo ./bin/tobimaru -config tobimaru.yaml
   ```

### macOS

macOS support has several limitations:
- Cannot capture while connected to WiFi on the same adapter
- No frame injection (active countermeasures unavailable)
- Channel switching has 1-3 second overhead (adjust dwell time accordingly)
- Requires BPF device permissions (run as root)

Setup steps:

1. Identify your WiFi interface (typically `en0`):

   ```bash
   ifconfig | grep -B2 "status: active"
   ```

2. Disconnect from WiFi before capturing (macOS cannot monitor while connected on the same adapter).

3. Run as root:

   ```bash
   sudo ./bin/tobimaru -config tobimaru.yaml
   ```

4. Recommended macOS configuration adjustments:

   ```yaml
   monitor:
     channel_hopping:
       dwell: 2s  # Increase from default 300ms due to slow channel switching
   ```

## Configuration

Tobimaru reads a YAML configuration file. Copy the annotated sample as a starting point:

```bash
cp configs/tobimaru.yaml tobimaru.yaml
```

### Configuration Reference

#### `log` — Logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `format` | string | `text` | Output format: `text` (human-readable) or `json` (structured) |

#### `monitor` — WiFi Interface

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface` | string | — | **Required.** WiFi interface name (e.g., `wlan0`, `en0`) |

#### `monitor.capture` — Packet Capture

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `snaplen` | int | `65535` | Maximum bytes captured per frame |
| `buffer_size` | int | `2097152` | Kernel buffer size in bytes (2 MB) |
| `promiscuous` | bool | `true` | Enable promiscuous mode |
| `timeout` | duration | `100ms` | Read timeout for pcap handle |

#### `monitor.channel_hopping` — Channel Scanning

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable channel hopping |
| `dwell` | duration | `300ms` | Base time spent on each channel |
| `channels_2ghz` | []int | `[1..13]` | 2.4 GHz channels to scan |
| `include_5ghz` | bool | `false` | Enable 5 GHz band scanning |
| `channels_5ghz` | []int | — | 5 GHz channels (when enabled) |

#### `monitor.channel_hopping.weighted_dwell` — Priority Channels

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Give primary channels more dwell time |
| `primary_channels` | []int | `[1, 6, 11]` | Channels with extended dwell |
| `multiplier` | float | `2.5` | Dwell time multiplier for primary channels |

Primary channels (1, 6, 11) are the most commonly used non-overlapping 2.4 GHz channels. Weighted dwell gives them more monitoring time.

#### `detection` — Detection Engine

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch for detection engine |
| `dedup_window` | duration | `30s` | Suppress duplicate alerts within this window |
| `alert_buffer_size` | int | `256` | Buffered alerts channel capacity |

### Configuration Validation

Tobimaru validates the configuration on startup with strict parsing:
- Unknown YAML keys are rejected (no typo-induced silent failures)
- `monitor.interface` is required — startup fails without it
- Numeric values must be positive where applicable
- All validation errors are reported at once

### Minimal Configuration

```yaml
monitor:
  interface: wlan0
```

All other fields use sensible defaults.

## Running

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `-config <path>` | Path to YAML configuration file (default: `tobimaru.yaml`) |
| `-version` | Print version information and exit |

### Basic Usage

```bash
# Run with explicit config
sudo ./bin/tobimaru -config /etc/tobimaru/tobimaru.yaml

# Print version
./bin/tobimaru -version
# Output: Tobimaru v1.0.0 (commit: abc1234, built: 2026-01-15T10:30:00Z)
```

### What Happens on Startup

1. Configuration is loaded and validated
2. Logger is initialized (writes to stdout)
3. Platform capabilities are detected and limitations logged
4. WiFi interface is switched to monitor mode
5. Packet capture begins with BPF filter for all 802.11 frame types
6. Channel hopper starts cycling through configured channels
7. Detection engine begins processing frames (if enabled)

### Stopping

Send SIGINT (Ctrl+C) or SIGTERM to stop gracefully:
- Detection engine stops processing
- Channel hopper stops
- Packet capture closes
- WiFi interface is restored from monitor mode
- All cleanup hooks execute in reverse order (LIFO)

The shutdown process has a 30-second deadline. If cleanup exceeds this, remaining hooks are skipped and the process exits.

## Log Output

### Text Format (default)

```
time=2026-01-15T10:30:00.000Z level=INFO msg="starting tobimaru" version=1.0.0 commit=abc1234
time=2026-01-15T10:30:00.010Z level=INFO msg="platform capabilities detected" monitor_mode=true frame_injection=true
time=2026-01-15T10:30:00.050Z level=INFO msg="capture pipeline started" interface=wlan0 channel=1
time=2026-01-15T10:30:05.100Z level=WARN msg="security event" type=deauth_flood severity=warning src=aa:bb:cc:dd:ee:ff bssid=11:22:33:44:55:66
```

### JSON Format

```json
{"time":"2026-01-15T10:30:00.000Z","level":"INFO","msg":"starting tobimaru","version":"1.0.0","commit":"abc1234"}
```

Use JSON format for log aggregation systems (ELK, Loki, etc.):

```yaml
log:
  format: json
```

### Debug Logging

Enable debug level to see per-frame information:

```yaml
log:
  level: debug
```

This produces high-volume output showing every parsed frame — useful for troubleshooting but not recommended for production.

## Security Events

When the detection engine is enabled, security events are emitted with three severity levels:

| Severity | Meaning |
|----------|---------|
| `info` | Informational — notable activity, no immediate threat |
| `warning` | Suspicious activity — potential attack in progress |
| `critical` | High-confidence attack detected — immediate attention needed |

Events are deduplicated by `(event_type, source_mac, bssid)` within the configured `dedup_window` to prevent alert fatigue.

## Troubleshooting

### "monitor mode not supported"

- Ensure your WiFi adapter supports monitor mode
- On Linux: check with `iw phy <phy> info | grep monitor`
- On macOS: built-in adapters support monitor mode via BPF (CoreWLAN for channel hopping)

### "interface not found"

- Verify the interface name: `iw dev` (Linux) or `ifconfig` (macOS)
- Ensure the interface is not already in use by another process

### "permission denied" / "BPF device"

- Run with `sudo` — monitor mode and raw capture require root privileges

### High CPU usage

- Increase `monitor.capture.timeout` to reduce polling frequency
- Disable debug logging
- Reduce the number of scanned channels

### macOS: slow channel switching

- Set `dwell` to 2 seconds or more
- macOS channel switching via CoreWLAN has 1-3 second overhead; setting dwell below this causes the hopper to spend most time switching rather than capturing
