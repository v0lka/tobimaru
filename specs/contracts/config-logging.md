# Contract: Config → Logging

## Boundary Rule

`internal/logging` depends on `internal/config` for the `LogConfig` type ONLY. `internal/config` does NOT import `internal/logging`. Data flows one direction: config struct → logger factory.

## Interfaces

| Interface | Package | Consumed By | Purpose |
|-----------|---------|-------------|---------|
| `config.LogConfig` (struct) | `internal/config` | `internal/logging` | Log level and format configuration |
| `logging.New(cfg config.LogConfig) *slog.Logger` | `internal/logging` | `cmd/tobimaru` | Logger factory |

## Initialization

In `cmd/tobimaru/main.go`:

```go
cfg, err := config.Load(*flagConfig)       // Step 1: load config
// ... error handling ...
logger := logging.New(cfg.Log)             // Step 2: create logger from LogConfig subset
slog.SetDefault(logger)                    // Step 3: set as default logger
```

The `cfg.Log` field is extracted from the full `*config.Config` and passed directly to `logging.New()`. The logging package receives only `LogConfig`, not the entire `Config` — it knows nothing about `MonitorConfig` or any future config sections.

## Data Flow Across Boundary

```
config.Config.Log (LogConfig)
    │
    │  {Level: "info", Format: "json"}
    ▼
logging.New(LogConfig)
    │
    │  parseLevel → slog.Level
    │  format → JSONHandler or TextHandler
    ▼
*slog.Logger
```

Direction: `internal/config` → `internal/logging` (one-way). The full `Config` does NOT cross the boundary — only the `LogConfig` subset.

## Error Propagation

`logging.New()` always succeeds — it never returns an error. Invalid level or format strings fall back to defaults (`slog.LevelInfo` and `TextHandler` respectively). The `config` package's validation ensures `LogConfig` fields are valid before they reach `logging.New()`.

## Breaking Change Checklist

If you change `LogConfig`:
- [ ] Update `config.LogConfig` struct definition
- [ ] Update `logging.New()` to handle new fields
- [ ] Update `configs/tobimaru.yaml` sample with new fields
- [ ] Update `applyDefaults()` in `internal/config/defaults.go` for new default values
- [ ] Update `validate()` in `internal/config/validation.go` for new validation rules
- [ ] Add or update test cases in both `internal/config/config_test.go` and `internal/logging/logging_test.go`
