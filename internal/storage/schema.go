package storage

// schemaVersion tracks the current schema version for migrations.
const schemaVersion = 1

// schemaSQL contains DDL statements for the initial schema creation.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    src_mac     TEXT,
    dst_mac     TEXT,
    bssid       TEXT,
    ssid        TEXT,
    channel     INTEGER,
    rssi        INTEGER,
    frame_count INTEGER,
    duration_ns INTEGER,
    metadata    TEXT,
    description TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    aps_json     TEXT NOT NULL,
    clients_json TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp);

CREATE TABLE IF NOT EXISTS whitelist (
    mac        TEXT PRIMARY KEY,
    ssid       TEXT,
    comment    TEXT,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blacklist (
    mac        TEXT PRIMARY KEY,
    reason     TEXT,
    comment    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

// pragmasSQL contains performance and reliability pragmas applied at open.
const pragmasSQL = `
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA cache_size=-8000;
`
