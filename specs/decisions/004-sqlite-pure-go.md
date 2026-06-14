# ADR-004: Pure-Go SQLite via modernc.org/sqlite

## Status

Accepted

## Context

Phase 3 requires persistent storage for security events, network state snapshots, and whitelist/blacklist data. SQLite is the natural choice for a single-binary daemon (no external database dependencies, ACID transactions, zero configuration). The question was which Go SQLite driver to use.

## Decision

Use `modernc.org/sqlite` — a pure-Go SQLite implementation that compiles the C SQLite source to Go via automatic transpilation.

## Consequences

**Positive:**
- No CGO dependency — `CGO_ENABLED=0` builds work without a C compiler
- Cross-compilation for Linux amd64/arm64 and macOS arm64 works seamlessly
- No system-level libsqlite3 dependency to manage across platforms
- Future OpenWrt (Phase 10) cross-compilation to MIPS/ARM is feasible
- Single binary deployment maintained (no .so/.dylib to ship)

**Negative:**
- Binary size increases by approximately 10-15 MB (transpiled C → Go code)
- Slightly slower than native CGO `mattn/go-sqlite3` for high-throughput writes (~20-30% overhead in benchmarks)
- Larger dependency tree (`modernc.org/libc`, `modernc.org/mathutil`, `modernc.org/memory`)

**Mitigations:**
- Performance overhead is acceptable for Tobimaru's write patterns (events at detection rate, snapshots every 5 minutes)
- Binary size is acceptable for desktop/server targets; for OpenWrt, UPX compression will be applied in Phase 10
- WAL mode + single-writer pattern eliminate most contention concerns

## Alternatives Considered

**`github.com/mattn/go-sqlite3` (CGO-based):**
- Fastest performance, mature, widely used
- Rejected because: requires C compiler for builds, complicates cross-compilation pipeline, breaks `CGO_ENABLED=0` requirement for portable binaries

**`zombiezen.com/go/sqlite` (wrapper over modernc.org/sqlite):**
- Provides a nicer, more Go-idiomatic API
- Rejected because: adds another dependency layer for marginal API improvement; `database/sql` interface from `modernc.org/sqlite` is sufficient and more familiar to Go developers
