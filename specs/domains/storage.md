# Storage Layer

## Purpose

Provides persistent storage for Tobimaru via SQLite. Stores security events, network state snapshots, whitelist/blacklist entries, and configuration key-value pairs. Uses the Repository pattern to decouple storage logic from consumers.

## Key Files

- `internal/storage/storage.go` — `Repository` interface, `EventFilter` type
- `internal/storage/sqlite.go` — `SQLiteRepository` implementation, `Open()`, all CRUD methods
- `internal/storage/schema.go` — DDL statements, schema version, migration logic, pragmas
- `internal/storage/sqlite_test.go` — integration tests using `:memory:` databases

## Core Types

```go
// ErrNotFound is returned when a queried item does not exist (wraps sql.ErrNoRows).
var ErrNotFound = errors.New("storage: not found")

type Repository interface {
    Close() error

    // Security Events
    SaveEvent(ctx, *detector.SecurityEvent) error
    ListEvents(ctx, EventFilter) ([]*detector.SecurityEvent, error)
    CountEvents(ctx, EventFilter) (int64, error)
    PruneEvents(ctx, maxCount int) (int64, error)

    // State Snapshots
    SaveSnapshot(ctx, *state.Snapshot) error
    LatestSnapshot(ctx) (*state.Snapshot, error)
    PruneSnapshots(ctx, maxCount int) (int64, error)

    // Whitelist / Blacklist
    SaveWhitelistEntry(ctx, *state.WhitelistEntry) error
    DeleteWhitelistEntry(ctx, mac string) error
    ListWhitelist(ctx) ([]*state.WhitelistEntry, error)
    SaveBlacklistEntry(ctx, *state.BlacklistEntry) error
    DeleteBlacklistEntry(ctx, mac string) error
    ListBlacklist(ctx) ([]*state.BlacklistEntry, error)

    // Configuration KV
    GetConfig(ctx, key string) (string, error)
    SetConfig(ctx, key, value string) error

    // Sessions (API authentication)
    CreateSession(ctx, *Session) error
    GetSession(ctx, token string) (*Session, error)
    DeleteSession(ctx, token string) error
    PruneExpiredSessions(ctx, now time.Time) (int64, error)
}

type Session struct {
    Token     string    // opaque random session identifier (URL-safe base64)
    Role      string    // "admin" or "user"
    CreatedAt time.Time // issuance time
    ExpiresAt time.Time // absolute expiration time
}

const (
    SessionRoleAdmin = "admin"
    SessionRoleUser  = "user"
)

type EventFilter struct {
    Since, Until time.Time
    EventType    string
    MinSeverity  detector.Severity
    Limit, Offset int
}

type SQLiteRepository struct { db *sql.DB; cfg config.StorageConfig }
func Open(cfg config.StorageConfig) (*SQLiteRepository, error)
```

## Flow

### Database Initialization

```
storage.Open(cfg)
  │
  ├─► sql.Open("sqlite", path + "?_txlock=immediate")
  │
  ├─► Apply pragmas: WAL mode, busy_timeout=5000, synchronous=NORMAL, cache_size=-8000
  │
  ├─► migrate(ctx, db):
  │     ├─ Check schema_version table exists
  │     ├─ If not: execute full schemaSQL DDL, insert version=1
  │     └─ If exists: check version, apply incremental migrations (future)
  │
  ├─► SetMaxOpenConns(1) — SQLite is single-writer
  │
  └─► Return *SQLiteRepository
```

### Schema

Tables: `schema_version`, `events`, `snapshots`, `whitelist`, `blacklist`, `config`, `sessions`

Indexes: `idx_events_timestamp`, `idx_events_type`, `idx_events_severity`, `idx_snapshots_timestamp`

### Snapshot Persistence

State snapshots serialize `[]*APInfo` and `[]*ClientInfo` as JSON into TEXT columns. This avoids complex relational schema for frequently-changing volatile data.

### Pruning

`PruneEvents(maxCount)` and `PruneSnapshots(maxCount)` delete the oldest records beyond the retention limit using `DELETE WHERE id NOT IN (SELECT id ... ORDER BY timestamp DESC LIMIT ?)`.

## Invariants

- `Open()` applies WAL mode and pragmas before any user operations
- Schema migration is idempotent — calling `migrate` on an already-migrated database is a no-op
- `MaxOpenConns(1)` ensures a single writer — prevents SQLite "database is locked" errors
- All methods accept `context.Context` for timeout/cancellation
- MAC addresses are stored as uppercase strings for consistency
- Timestamps are stored as RFC3339Nano text for full precision
- Event metadata is stored as JSON text
- `ErrNotFound` is returned for missing config keys (not `sql.ErrNoRows`)
- Snapshot JSON fields use struct tags from `state.APInfo` and `state.ClientInfo`

## Configuration

| YAML path | Go field | Type | Default | Required |
|-----------|----------|------|---------|----------|
| `storage.enabled` | `StorageConfig.Enabled` | `bool` | `false` | No |
| `storage.path` | `StorageConfig.Path` | `string` | `"tobimaru.db"` | No |
| `storage.snapshot_interval` | `StorageConfig.SnapshotInterval` | `time.Duration` | `5m` | No |
| `storage.max_snapshots` | `StorageConfig.MaxSnapshots` | `int` | `288` | No |
| `storage.max_events` | `StorageConfig.MaxEvents` | `int` | `100000` | No |

## Extension Points

- **Adding a new storage backend:** implement the `Repository` interface (e.g., PostgreSQL, file-based)
- **Adding a new table:** add DDL to `schemaSQL`, bump `schemaVersion`, add migration logic
- **Adding event export:** use `ListEvents` with filters to export to external systems
- **Adding full-text search:** add FTS5 virtual table for event descriptions/metadata

## Related Specs

- [Network State](state.md) — provides `Snapshot`, `WhitelistEntry`, `BlacklistEntry` types for persistence
- [Detection Engine](detection.md) — provides `SecurityEvent` type stored by `SaveEvent()`
- [Configuration](configuration.md) — `StorageConfig` drives storage parameters
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — Repository is opened and closed by `cmd/tobimaru`
- [ADR-004: Pure-Go SQLite](../decisions/004-sqlite-pure-go.md) — why `modernc.org/sqlite` was chosen
