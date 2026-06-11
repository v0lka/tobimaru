# User Guide

This guide covers installing, configuring, and running Tobimaru on Linux and macOS.

## Installation

### Building from Source

Requirements:

- Go 1.26 or later (the module declares `go 1.26.3`)
- GNU Make
- Node.js 22+ and `npm` — only required when rebuilding the embedded web dashboard

```bash
git clone https://github.com/vkochetkov/tobimaru.git
cd tobimaru
make build
```

The binary is placed in `bin/tobimaru`. A pre-built dashboard bundle is committed
to `internal/api/web/dist/`, so `make build` produces a fully functional binary
without running `make web`. Run `make web-deps && make web` only when the SPA sources change.
`make web-deps` must be run before `make web` to install TypeScript and other Node dependencies.

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
   sudo ./bin/tobimaru -config configs/tobimaru.yaml
   ```

### macOS

macOS support has several limitations:

- Cannot capture while connected to WiFi on the same adapter
- No frame injection (active countermeasures unavailable)
- Channel switching has 1-3 second overhead — use a higher dwell time
- Requires BPF device permissions (run as root)
- Channel hopping uses the built-in CoreWLAN bridge — no `airport` utility needed

Setup steps:

1. Identify your WiFi interface (typically `en0`):

   ```bash
   ifconfig | grep -B2 "status: active"
   ```

2. Disconnect from WiFi before capturing (macOS cannot monitor while connected
   on the same adapter).

3. Run as root:

   ```bash
   sudo ./bin/tobimaru -config configs/tobimaru.yaml
   ```

4. Recommended macOS configuration adjustments:

   ```yaml
   monitor:
     channel_hopping:
       dwell: 2s  # Increase from default 300ms due to slow channel switching
   ```

See `docs/development/macos-setup.md` for ChmodBPF and LaunchDaemon recipes.

## Configuration

Tobimaru reads a YAML configuration file. Copy the annotated sample as a
starting point:

```bash
cp configs/tobimaru.yaml tobimaru.yaml
```

The default `-config` value is `configs/tobimaru.yaml`. Pass `-config` to point
at a custom path.

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
| `frame_buffer_size` | int | `1024` | Capacity of the parsed-frame channel |
| `promiscuous` | bool | `true` | Enable promiscuous mode |
| `timeout` | duration | `100ms` | Read timeout for the pcap handle |

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

Primary channels (1, 6, 11) are the most commonly used non-overlapping 2.4 GHz
channels. Weighted dwell gives them more monitoring time.

#### `detection` — Detection Engine

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for the detection engine |
| `dedup_window` | duration | `30s` | Suppress duplicate alerts within this window |
| `alert_buffer_size` | int | `256` | Buffered alerts channel capacity |

The engine ships with five rules. Each rule is configured under `detection.<rule_name>`:

| Rule | YAML key | Default `enabled` | Notes |
|------|----------|-------------------|-------|
| Deauthentication flood | `deauth_flood` | `true` | Sliding-window counter on deauth frames |
| Disassociation flood | `disassoc_flood` | `true` | Sliding-window counter on disassoc frames |
| Beacon flood | `beacon_flood` | `true` | Spike of unique BSSIDs after a learning period |
| Evil Twin AP | `evil_twin` | `true` | SSID/BSSID/IE divergence with score threshold |
| Unauthorized device | `unauthorized_device` | `false` | Whitelist lookup; requires `protected_bssids`/`protected_ssids` |

Common rule fields:

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Toggle for that rule |
| `threshold` | int | Trigger threshold (flood rules) |
| `window` | duration | Sliding-window length (flood rules) |
| `learning_period` | duration | Initial mute window (`beacon_flood`, `evil_twin`) |
| `score_threshold` | int | Cumulative score before alerting (`evil_twin`) |
| `stale_timeout` | duration | Forget APs after this (`evil_twin`) |
| `min_beacons` | int | Minimum beacons before scoring (`evil_twin`) |
| `protected_bssids` | []string | Defended AP MACs (`unauthorized_device`) |
| `protected_ssids` | []string | Defended SSIDs (`unauthorized_device`) |
| `whitelist` | []string | Allowed client MACs (`unauthorized_device`) |
| `alert_on_probe` | bool | Alert on probe requests (`unauthorized_device`) |
| `cooldown` | duration | Per-MAC mute (`unauthorized_device`) |

Set `detection.enabled: true` to start emitting alerts. The shipped
`configs/tobimaru.yaml` keeps detection disabled by default so the daemon can
be exercised in capture-only mode.

#### `state` — Network State Engine

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Track APs and clients in memory |
| `ttl` | duration | `10m` | Drop entries unseen for this long |
| `sweep_interval` | duration | `1m` | How often eviction runs |

Disabling the state engine also disables snapshots, auto-learning and the
state-driven detection rules in the dashboard.

#### `whitelist.auto_learning` — Auto-Learning

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enter learning mode at startup |
| `duration` | duration | `15m` | Learning phase length |

While learning, every observed device is added to the in-memory whitelist (and
persisted if `storage.enabled` is true).

#### `storage` — SQLite Persistence

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for SQLite persistence |
| `path` | string | `tobimaru.db` | Database file (created with `0600` perms) |
| `snapshot_interval` | duration | `5m` | State snapshot cadence |
| `max_snapshots` | int | `288` | Snapshot retention (~24h at 5 min) |
| `max_events` | int | `100000` | Security event retention (pruned every 100 inserts) |

Tobimaru uses a pure-Go SQLite driver (no CGO). The file is created or
chmod-ed to `0600` on open.

#### `api` — HTTP API + Dashboard

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Start the HTTP server and serve the dashboard |
| `listen` | string | `127.0.0.1:8080` | Bind address (use a reverse proxy for remote access) |
| `read_timeout` | duration | `15s` | HTTP read timeout |
| `write_timeout` | duration | `30s` | HTTP write timeout (SSE bypasses this per-request) |
| `idle_timeout` | duration | `60s` | Idle keep-alive timeout |
| `shutdown_timeout` | duration | `5s` | Graceful HTTP shutdown deadline |
| `cors.allowed_origins` | []string | `[]` | Empty = same-origin only |
| `auth.enabled` | bool | `true` | Require login for the dashboard and API |
| `auth.session_ttl` | duration | `24h` | Session token lifetime |
| `auth.admin_password_hash` | string | — | bcrypt hash, required when `auth.enabled` is `true` |
| `auth.user_password_hash` | string | — | Optional read-only account; empty disables it |

When `auth.enabled` is `true`, `storage.enabled` MUST also be `true` because
sessions are persisted in SQLite.

### Configuration Validation

Tobimaru validates the configuration on startup with strict parsing:

- Unknown YAML keys are rejected (no typo-induced silent failures)
- `monitor.interface` is required — startup fails without it
- Numeric values must be positive where applicable
- All validation errors are reported at once via `errors.Join`

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
| `-config <path>` | Path to YAML configuration file (default: `configs/tobimaru.yaml`) |
| `-version` | Print version information and exit |
| `-hash-password <plaintext>` | Print a bcrypt hash for the given password and exit |

This flag is a built-in utility for generating bcrypt hashes to place in
the configuration file. The daemon never stores passwords in plaintext —
`auth.admin_password_hash` and `auth.user_password_hash` in the YAML config
accept only pre-hashed bcrypt values. Use this flag to generate the hash,
then copy the output into the config. No external tools are needed.

### Basic Usage

```bash
# Run with explicit config
sudo ./bin/tobimaru -config /etc/tobimaru/tobimaru.yaml

# Print version
./bin/tobimaru -version
# Output: Tobimaru v1.0.0 (commit: abc1234, built: 2026-01-15T10:30:00Z)

# Generate a bcrypt hash for the dashboard admin/user password.
# Copy the output into auth.admin_password_hash or auth.user_password_hash
# in the YAML config file.
./bin/tobimaru -hash-password 'mypassword'
```

### What Happens on Startup

1. CLI flags are parsed (`-config`, `-version`, `-hash-password`).
2. The YAML configuration is loaded and validated.
3. The structured logger is initialized.
4. SQLite storage is opened (when `storage.enabled`).
5. The state engine is created and persisted whitelist/blacklist are loaded.
6. The detection engine is created; rules are registered based on which
   `detection.<rule>.enabled` flags are set. Startup logs a warning if
   detection is enabled but no rules registered.
7. The capture pipeline is created and started: monitor mode is enabled,
   the pcap handle opens, the channel hopper begins cycling.
8. Shutdown hooks are registered (capture stop, storage close, API stop).
9. Frame consumers start based on enabled features:
   - When detection and state are both active, a fan-out duplicates frames
     between the detection and state pipelines.
   - The detection engine, alert consumer, state-frame consumer and state
     eviction goroutines run concurrently.
   - When storage is enabled, a periodic snapshot writer persists AP/client
     state.
   - Auto-learning runs once if enabled.
10. When `api.enabled`, the HTTP server, SSE hub and a periodic status
    publisher start.
11. The process blocks until SIGINT/SIGTERM.
12. Shutdown hooks execute in LIFO order with a 30-second deadline.

### Stopping

Send SIGINT (Ctrl+C) or SIGTERM to stop gracefully:

- The detection engine and state engine drain.
- The channel hopper stops.
- The pcap handle is closed.
- The WiFi interface is restored from monitor mode.
- The HTTP server and SSE hub shut down.
- All cleanup hooks execute in reverse order (LIFO).

The shutdown process has a 30-second deadline. If cleanup exceeds this, the
remaining hooks are skipped and the process exits.

## Web Dashboard

Enable both `api.enabled: true` and `storage.enabled: true`, set
`auth.admin_password_hash` (use `-hash-password`), and start the daemon:

```bash
sudo ./bin/tobimaru -config configs/tobimaru.yaml
# Dashboard at http://127.0.0.1:8080
# REST API mounted under /api/
```

The dashboard ships pages for Status, Map (APs and clients), Events, Stats,
Settings and Login. It is built into `internal/api/web/dist/` and embedded in
the binary at compile time, so no extra files need to be deployed.

For development with hot reload:

```bash
# Terminal 1: backend
sudo ./bin/tobimaru -config configs/tobimaru.yaml

# Terminal 2: frontend dev server
cd web && npm run dev
# Opens at http://localhost:5173, proxies /api to 127.0.0.1:8080
```

## Log Output

### Text Format (default)

```
time=2026-01-15T10:30:00.000Z level=INFO msg="Tobimaru WiFi Watchdog starting" version=1.0.0 commit=abc1234
time=2026-01-15T10:30:00.010Z level=INFO msg="platform capabilities" monitor_mode=true frame_injection=true
time=2026-01-15T10:30:00.050Z level=INFO msg="capture started" interface=wlan0 channel_hopping=true
time=2026-01-15T10:30:05.100Z level=ERROR msg="security alert" type=deauth_flood severity=critical src_mac=aa:bb:cc:dd:ee:ff bssid=11:22:33:44:55:66
```

### JSON Format

```json
{"time":"2026-01-15T10:30:00.000Z","level":"INFO","msg":"Tobimaru WiFi Watchdog starting","version":"1.0.0","commit":"abc1234"}
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

This produces high-volume output showing every parsed frame — useful for
troubleshooting but not recommended for production.

## Security Events

When the detection engine is enabled, security events are emitted with three
severity levels:

| Severity | Meaning |
|----------|---------|
| `info` | Informational — notable activity, no immediate threat |
| `warning` | Suspicious activity — potential attack in progress |
| `critical` | High-confidence attack detected — immediate attention needed |

Events are deduplicated by `(event_type, source_mac, bssid)` within the
configured `dedup_window` to prevent alert fatigue.

## Troubleshooting

### "monitor mode not supported"

- Ensure your WiFi adapter supports monitor mode.
- On Linux: check with `iw phy <phy> info | grep monitor`.
- On macOS: built-in adapters support monitor mode via BPF (CoreWLAN handles
  channel hopping).

### "interface not found"

- Verify the interface name: `iw dev` (Linux) or `ifconfig` (macOS).
- Ensure the interface is not already in use by another process.

### "permission denied" / "BPF device"

- Run with `sudo` — monitor mode and raw capture require root privileges.

### High CPU usage

- Increase `monitor.capture.timeout` to reduce polling frequency.
- Disable debug logging.
- Reduce the number of scanned channels.

### macOS: slow channel switching

- Set `dwell` to 2 seconds or more.
- macOS channel switching via CoreWLAN has 1-3 seconds of overhead; setting
  dwell below this causes the hopper to spend most time switching rather than
  capturing.

### Auth misconfiguration

- `api.auth.enabled: true` requires `storage.enabled: true` and a non-empty
  `admin_password_hash`. Generate hashes with
  `./bin/tobimaru -hash-password 'plaintext'`.
