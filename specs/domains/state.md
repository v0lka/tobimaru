# Network State Engine

## Purpose

Maintains a real-time in-memory map of the WiFi radio environment by consuming parsed 802.11 frames. Tracks Access Points (by BSSID) and client devices (by MAC), evicts stale entries by TTL, and provides whitelist/blacklist management with an auto-learning mode.

## Key Files

- `internal/state/state.go` — `Engine` struct, `NewEngine()`, `ProcessFrame()`, `RunEviction()`, `Snapshot()`
- `internal/state/ap.go` — `APInfo` struct, `APMap` (thread-safe BSSID→APInfo map with eviction)
- `internal/state/client.go` — `ClientInfo` struct, `ClientMap` (thread-safe MAC→ClientInfo map with eviction)
- `internal/state/whitelist.go` — `WhitelistEngine`, `WhitelistEntry`, `BlacklistEntry`, CRUD operations
- `internal/state/learning.go` — `LearningMode`, auto-learning timer and whitelist generation
- `internal/state/state_test.go` — tests for engine, ProcessFrame, eviction, snapshot
- `internal/state/ap_test.go` — tests for APMap CRUD and eviction
- `internal/state/client_test.go` — tests for ClientMap CRUD and eviction
- `internal/state/whitelist_test.go` — tests for whitelist/blacklist CRUD
- `internal/state/learning_test.go` — tests for auto-learning mode

## Core Types

```go
type Engine struct { /* cfg, aps, clients, whitelist, logger */ }

func NewEngine(cfg config.StateConfig, wlCfg config.WhitelistConfig, logger *slog.Logger) *Engine
func (e *Engine) ProcessFrame(frame *parser.ParsedFrame)
func (e *Engine) RunEviction(ctx context.Context)
func (e *Engine) Snapshot() *Snapshot
func (e *Engine) APs() *APMap
func (e *Engine) Clients() *ClientMap
func (e *Engine) Whitelist() *WhitelistEngine

type APInfo struct {
    BSSID, SSID, Channel, RSSI, Capability, BeaconInterval, InfoElements,
    FirstSeen, LastSeen, BeaconCount, Hidden
}

type ClientInfo struct {
    MAC, BSSID, SSID, Channel, RSSI, FirstSeen, LastSeen, FrameCount,
    Associated, ProbeSSIDs
}

type Snapshot struct {
    Timestamp time.Time
    APs       []*APInfo
    Clients   []*ClientInfo
}
```

## Flow

### Frame Processing

```
Engine.ProcessFrame(frame)
  │
  └─► switch frame.FrameType:
        ├─ Beacon         → Upsert AP: BSSID, SSID, channel, RSSI, IEs, BeaconCount++
        ├─ ProbeResponse  → Upsert AP: BSSID, SSID, channel, RSSI, IEs
        ├─ ProbeRequest   → Upsert client: SrcMAC, add SSID to ProbeSSIDs
        ├─ AssocReq/ReassocReq → Upsert client: SrcMAC, BSSID, Associated=true
        ├─ AssocResp/ReassocResp (status=0) → Confirm association for DstMAC
        ├─ Deauth/Disassoc → Mark client Associated=false
        └─ Data/QoSData   → Upsert client: infer MAC from ToDS/FromDS, FrameCount++
```

### TTL Eviction

```
Engine.RunEviction(ctx)
  │
  └─► ticker at cfg.SweepInterval:
        ├─ cutoff = now - cfg.TTL
        ├─ aps.Evict(cutoff)     → remove APs with LastSeen < cutoff
        └─ clients.Evict(cutoff) → remove clients with LastSeen < cutoff
```

### Auto-Learning

```
LearningMode.Run(ctx)
  │
  ├─► Set active = true, log start
  ├─► Wait cfg.Duration (timer) or ctx cancellation
  ├─► On timer: iterate all associated clients → build WhitelistEntry slice
  ├─► BulkAddWhitelist(entries) to in-memory engine
  └─► Return entries for caller to persist via storage
```

## Invariants

- `ProcessFrame` handles nil frames safely (returns immediately)
- AP and client maps use `sync.RWMutex` for concurrent access safety
- `Update()` on APMap/ClientMap preserves `FirstSeen` — only dynamic fields are merged
- Eviction removes entries strictly based on `LastSeen < cutoff` — no approximation
- Whitelist MAC keys are normalized to uppercase for case-insensitive lookup
- Auto-learning only whitelists clients with `Associated == true`
- The state engine does not import `internal/capture` or `internal/storage` (leaf consumer)

## Configuration

| YAML path | Go field | Type | Default | Required |
|-----------|----------|------|---------|----------|
| `state.enabled` | `StateConfig.Enabled` | `bool` | `false` | No |
| `state.ttl` | `StateConfig.TTL` | `time.Duration` | `10m` | No |
| `state.sweep_interval` | `StateConfig.SweepInterval` | `time.Duration` | `1m` | No |
| `whitelist.auto_learning.enabled` | `AutoLearningConfig.Enabled` | `bool` | `false` | No |
| `whitelist.auto_learning.duration` | `AutoLearningConfig.Duration` | `time.Duration` | `15m` | No |

## Extension Points

- **Adding a new frame type handler:** add a case to the switch in `ProcessFrame()`
- **Adding a new field to APInfo/ClientInfo:** update the struct, the processing function, and add JSON tag for snapshot serialization
- **Adding whitelist match criteria:** extend `WhitelistEntry` with additional fields (e.g., BSSID, channel) and update `IsWhitelisted` logic
- **Adding device fingerprinting:** extend `ClientInfo` with fingerprint data, populate from ProbeRequest IEs

## Related Specs

- [Configuration](configuration.md) — `StateConfig`, `WhitelistConfig` drive the engine
- [802.11 Frame Parser](parser.md) — `ParsedFrame` is the input to `ProcessFrame()`
- [Storage](storage.md) — persists snapshots, whitelist/blacklist entries
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — Engine is created and started by `cmd/tobimaru`
