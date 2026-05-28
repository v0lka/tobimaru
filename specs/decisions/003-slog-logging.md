# ADR-003: slog as Structured Logging Library

## Status

Accepted

## Context

The daemon needs structured logging with configurable levels and output formats. Requirements:
- JSON output for production (log aggregation, parsing)
- Text output for development (human-readable)
- Configurable level: debug, info, warn, error
- Minimal dependencies — the project aims for small binary size
- Thread-safe by default (concurrent goroutines for capture, hopping, detection)

Go structured logging options: `log/slog` (stdlib, Go 1.21+), `uber-go/zap`, `rs/zerolog`, `sirupsen/logrus`.

## Decision

Use **`log/slog`** from the Go standard library. Wrapped in a thin `internal/logging` package that creates a `*slog.Logger` from `config.LogConfig`.

The factory function `logging.New()` maps string-based level and format selections to `slog.Handler` options, writing to `os.Stdout`.

## Consequences

**Positive:**
- Zero dependencies — part of Go stdlib since 1.21
- Structured logging with both JSON and text handlers built in
- `slog.SetDefault()` makes the logger available globally without passing it explicitly
- Handler-based design: swap handlers for different output formats without changing log calls
- Designed for high-performance concurrent use (lock-free buffering)
- Well-documented and widely adopted across the Go ecosystem

**Negative:**
- Go 1.21+ requirement — but Go 1.22 is already the project's minimum CI version
- slog is less feature-rich than zap (no sampling, no dynamic level changes without creating a new logger)
- TextHandler output format is not configurable (unlike zerolog's ConsoleWriter)
- No built-in log rotation or file output — these must be added later if needed

## Alternatives Considered

| Alternative | Rejection Reason |
|-------------|-----------------|
| **`uber-go/zap`** | Powerful and fast, but adds a dependency. Overkill for Phase 0 — `slog` covers all current needs. Can be reconsidered if performance profiling shows slog as a bottleneck. |
| **`rs/zerolog`** | Zero-allocation JSON logging. Excellent performance, but adds a dependency and has a less idiomatic API (chained methods). |
| **`sirupsen/logrus`** | Older, in maintenance mode. Slower than slog and zap. Uses `interface{}` for fields (no type safety). Not recommended for new projects. |
| **`fmt.Println` / `log.Println`** | Unstructured. No level filtering. Can't output JSON. Not viable for a production daemon. |
