# Logging

## Purpose

Creates a configured `*slog.Logger` from a `LogConfig` struct, mapping string-based level and format selections to the Go standard library's `log/slog` package.

## Key Files

- `internal/logging/logging.go` — `New()` factory function, `parseLevel()` helper
- `internal/logging/logging_test.go` — unit tests for all log levels, formats, and fallback behavior

## Core Types

No custom types exported. The package exposes a factory function and runtime level accessors:

```go
func New(cfg config.LogConfig) *slog.Logger
func SetLevel(s string) bool
func Level() string
```

- `New()` creates a logger backed by a package-level `slog.LevelVar`. All loggers share this LevelVar, enabling runtime adjustments.
- `SetLevel(s)` atomically updates the effective log level. Accepts `"debug"`, `"info"`, `"warn"`, `"error"`. Returns `false` for unknown strings.
- `Level()` returns the current effective level as a string.

## Behavior

### `New(cfg config.LogConfig) *slog.Logger`

1. Maps `cfg.Level` to `slog.Level` via `parseLevel()`:
   - `"debug"` → `slog.LevelDebug`
   - `"info"` → `slog.LevelInfo`
   - `"warn"` → `slog.LevelWarn`
   - `"error"` → `slog.LevelError`
   - Anything else → `slog.LevelInfo` (defensive fallback; config validation catches this earlier)
2. Creates a `slog.HandlerOptions` with the mapped level
3. Selects handler based on `cfg.Format`:
   - `"json"` → `slog.NewJSONHandler(os.Stdout, opts)`
   - Anything else → `slog.NewTextHandler(os.Stdout, opts)`
4. Returns `slog.New(handler)`

### `parseLevel(s string) slog.Level`

A simple switch-case mapping string names to `slog.Level` constants. The default case returns `slog.LevelInfo` for unknown strings.

## Flow

```
logging.New(LogConfig{Level: "info", Format: "text"})
  │
  ├─► parseLevel("info") → slog.LevelInfo
  │
  ├─► Select handler:
  │     Format=="json" ? JSONHandler : TextHandler
  │     → slog.NewTextHandler(os.Stdout, {Level: LevelInfo})
  │
  └─► return slog.New(handler)
```

In `cmd/tobimaru/main.go`, the returned logger is set as the default:
```go
logger := logging.New(cfg.Log)
slog.SetDefault(logger)
```

## Invariants

- The logger always writes to `os.Stdout`
- Unrecognized level strings fall back to `slog.LevelInfo` (the `config` package's `DefaultLogLevel`)
- Unrecognized format strings fall back to text handler
- Error-level messages (from `slog.Error()`) are always emitted regardless of configured level — `slog` treats Error as non-filterable by default

## Configuration

| Parameter | Values | Default | Source |
|-----------|--------|---------|--------|
| `log.level` | `debug`, `info`, `warn`, `error` | `"info"` | `config.LogConfig.Level` |
| `log.format` | `text`, `json` | `"text"` | `config.LogConfig.Format` |

## Extension Points

- **Adding a new log destination:** modify `New()` to accept an `io.Writer` parameter, or add a `Writer` field to `LogConfig`
- **Adding custom handler options:** pass additional `slog.HandlerOptions` fields (e.g., `AddSource`, `ReplaceAttr`)
- **Supporting log rotation:** add a `File` field to `LogConfig` and use a file writer with rotation library

## Related Specs

- [Configuration](configuration.md) — provides `LogConfig` type consumed here
- [Contract: Config → Logging](../contracts/config-logging.md) — formal boundary specification
- [ADR-003: slog Structured Logging](../decisions/003-slog-logging.md) — why `log/slog` was chosen
