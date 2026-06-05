package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/state"
)

// ErrNotFound is returned when a queried item does not exist.
var ErrNotFound = errors.New("storage: not found")

// memoryDSN is the SQLite DSN for an in-memory database. Treated specially
// in Open() because it has no on-disk file to chmod.
const memoryDSN = ":memory:"

// SQLiteRepository implements Repository using modernc.org/sqlite.
type SQLiteRepository struct {
	db  *sql.DB
	cfg config.StorageConfig
}

// Open creates a new SQLite repository, opening or creating the database file.
// It runs migrations and applies WAL mode + pragmas for performance.
//
// For on-disk databases, the file's permissions are tightened to 0600 after
// successful migration so that captured security events and state snapshots
// are not world-readable.
func Open(cfg config.StorageConfig) (*SQLiteRepository, error) {
	dsn := cfg.Path + "?_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to open database %q: %w", cfg.Path, err)
	}

	ctx := context.Background()

	// Apply performance pragmas.
	if _, err := db.ExecContext(ctx, pragmasSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: failed to apply pragmas: %w", err)
	}

	// Run schema migration.
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: migration failed: %w", err)
	}

	// Harden file permissions for on-disk databases. The :memory: DSN does
	// not produce a real file and must be skipped.
	if !isMemoryDSN(cfg.Path) {
		if err := os.Chmod(cfg.Path, 0o600); err != nil {
			db.Close()
			return nil, fmt.Errorf("storage: failed to set file permissions: %w", err)
		}
	}

	// Set connection pool limits for SQLite (single writer).
	db.SetMaxOpenConns(1)

	return &SQLiteRepository{db: db, cfg: cfg}, nil
}

// isMemoryDSN reports whether the given storage path refers to an in-memory
// SQLite database (no real file on disk).
func isMemoryDSN(path string) bool {
	return path == memoryDSN || strings.HasPrefix(path, "file:"+memoryDSN) || strings.Contains(path, "mode=memory")
}

// Close closes the underlying database connection.
func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}

// migrate ensures the database schema is at the current version.
func migrate(ctx context.Context, db *sql.DB) error {
	// Check if schema_version table exists.
	var count int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_version'").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check schema_version: %w", err)
	}

	if count == 0 {
		// Fresh database: create all tables.
		if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
			return fmt.Errorf("failed to create schema: %w", err)
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (?)", schemaVersion); err != nil {
			return fmt.Errorf("failed to record schema version: %w", err)
		}
		return nil
	}

	// Schema exists; check version for future migrations.
	var version int
	err = db.QueryRowContext(ctx, "SELECT version FROM schema_version LIMIT 1").Scan(&version)
	if err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}

	if version < schemaVersion {
		// IMPORTANT: When bumping schemaVersion above 1, do NOT just update
		// the version row. Implement migrations as sequential version-gated
		// blocks (e.g., `if version < 2 { ... }; if version < 3 { ... }`) so
		// that databases at any historical version can be upgraded
		// step-by-step. Never drop-and-recreate tables.
		if _, err := db.ExecContext(ctx, "UPDATE schema_version SET version = ?", schemaVersion); err != nil {
			return fmt.Errorf("failed to update schema version: %w", err)
		}
	}

	return nil
}

// --- Security Events ---

// SaveEvent persists a security event to the database.
func (r *SQLiteRepository) SaveEvent(ctx context.Context, event *detector.SecurityEvent) error {
	if event == nil {
		return nil
	}

	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO events (timestamp, event_type, severity, src_mac, dst_mac, bssid, ssid, channel, rssi, frame_count, duration_ns, metadata, description)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp.Format(time.RFC3339Nano),
		event.EventType,
		int(event.Severity),
		macToString(event.SrcMAC),
		macToString(event.DstMAC),
		macToString(event.BSSID),
		event.SSID,
		event.Channel,
		event.RSSI,
		event.FrameCount,
		event.Duration.Nanoseconds(),
		string(metadataJSON),
		event.Description,
	)
	return err
}

// ListEvents retrieves security events matching the given filter.
func (r *SQLiteRepository) ListEvents(ctx context.Context, filter EventFilter) ([]*detector.SecurityEvent, error) {
	query, args := buildEventQuery("SELECT id, timestamp, event_type, severity, src_mac, dst_mac, bssid, ssid, channel, rssi, frame_count, duration_ns, metadata, description FROM events", filter)
	query += " ORDER BY timestamp DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*detector.SecurityEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// CountEvents returns the count of events matching the filter.
func (r *SQLiteRepository) CountEvents(ctx context.Context, filter EventFilter) (int64, error) {
	query, args := buildEventQuery("SELECT COUNT(*) FROM events", filter)
	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// PruneEvents deletes the oldest events keeping at most maxCount.
// Returns the number of events deleted.
func (r *SQLiteRepository) PruneEvents(ctx context.Context, maxCount int) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY timestamp DESC LIMIT ?)`,
		maxCount,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// --- State Snapshots ---

// SaveSnapshot persists a state snapshot.
func (r *SQLiteRepository) SaveSnapshot(ctx context.Context, snap *state.Snapshot) error {
	if snap == nil {
		return nil
	}

	apsJSON, err := json.Marshal(snap.APs)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal APs: %w", err)
	}
	clientsJSON, err := json.Marshal(snap.Clients)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal clients: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO snapshots (timestamp, aps_json, clients_json) VALUES (?, ?, ?)`,
		snap.Timestamp.Format(time.RFC3339Nano),
		string(apsJSON),
		string(clientsJSON),
	)
	return err
}

// LatestSnapshot returns the most recent state snapshot.
func (r *SQLiteRepository) LatestSnapshot(ctx context.Context) (*state.Snapshot, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT timestamp, aps_json, clients_json FROM snapshots ORDER BY timestamp DESC LIMIT 1`,
	)

	var tsStr, apsStr, clientsStr string
	if err := row.Scan(&tsStr, &apsStr, &clientsStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid snapshot timestamp %q: %w", tsStr, err)
	}

	var aps []*state.APInfo
	if err := json.Unmarshal([]byte(apsStr), &aps); err != nil {
		return nil, fmt.Errorf("storage: failed to unmarshal APs: %w", err)
	}

	var clients []*state.ClientInfo
	if err := json.Unmarshal([]byte(clientsStr), &clients); err != nil {
		return nil, fmt.Errorf("storage: failed to unmarshal clients: %w", err)
	}

	return &state.Snapshot{
		Timestamp: ts,
		APs:       aps,
		Clients:   clients,
	}, nil
}

// PruneSnapshots deletes the oldest snapshots keeping at most maxCount.
func (r *SQLiteRepository) PruneSnapshots(ctx context.Context, maxCount int) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY timestamp DESC LIMIT ?)`,
		maxCount,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// --- Whitelist ---

// SaveWhitelistEntry inserts or replaces a whitelist entry.
func (r *SQLiteRepository) SaveWhitelistEntry(ctx context.Context, entry *state.WhitelistEntry) error {
	if entry == nil || entry.MAC == nil {
		return nil
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO whitelist (mac, ssid, comment, source, created_at) VALUES (?, ?, ?, ?, ?)`,
		strings.ToUpper(entry.MAC.String()),
		entry.SSID,
		entry.Comment,
		entry.Source,
		entry.CreatedAt.Format(time.RFC3339Nano),
	)
	return err
}

// DeleteWhitelistEntry removes a MAC from the whitelist.
func (r *SQLiteRepository) DeleteWhitelistEntry(ctx context.Context, mac string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM whitelist WHERE mac = ?`, strings.ToUpper(mac))
	return err
}

// ListWhitelist returns all whitelist entries.
func (r *SQLiteRepository) ListWhitelist(ctx context.Context) ([]*state.WhitelistEntry, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT mac, ssid, comment, source, created_at FROM whitelist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*state.WhitelistEntry
	for rows.Next() {
		var macStr, ssid, comment, source, createdStr string
		if err := rows.Scan(&macStr, &ssid, &comment, &source, &createdStr); err != nil {
			return nil, err
		}
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("storage: invalid whitelist MAC %q: %w", macStr, err)
		}
		created, err := time.Parse(time.RFC3339Nano, createdStr)
		if err != nil {
			return nil, fmt.Errorf("storage: invalid whitelist created_at %q: %w", createdStr, err)
		}
		entries = append(entries, &state.WhitelistEntry{
			MAC:       mac,
			SSID:      ssid,
			Comment:   comment,
			Source:    source,
			CreatedAt: created,
		})
	}
	return entries, rows.Err()
}

// --- Blacklist ---

// SaveBlacklistEntry inserts or replaces a blacklist entry.
func (r *SQLiteRepository) SaveBlacklistEntry(ctx context.Context, entry *state.BlacklistEntry) error {
	if entry == nil || entry.MAC == nil {
		return nil
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO blacklist (mac, reason, comment, created_at) VALUES (?, ?, ?, ?)`,
		strings.ToUpper(entry.MAC.String()),
		entry.Reason,
		entry.Comment,
		entry.CreatedAt.Format(time.RFC3339Nano),
	)
	return err
}

// DeleteBlacklistEntry removes a MAC from the blacklist.
func (r *SQLiteRepository) DeleteBlacklistEntry(ctx context.Context, mac string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM blacklist WHERE mac = ?`, strings.ToUpper(mac))
	return err
}

// ListBlacklist returns all blacklist entries.
func (r *SQLiteRepository) ListBlacklist(ctx context.Context) ([]*state.BlacklistEntry, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT mac, reason, comment, created_at FROM blacklist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*state.BlacklistEntry
	for rows.Next() {
		var macStr, reason, comment, createdStr string
		if err := rows.Scan(&macStr, &reason, &comment, &createdStr); err != nil {
			return nil, err
		}
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("storage: invalid blacklist MAC %q: %w", macStr, err)
		}
		created, err := time.Parse(time.RFC3339Nano, createdStr)
		if err != nil {
			return nil, fmt.Errorf("storage: invalid blacklist created_at %q: %w", createdStr, err)
		}
		entries = append(entries, &state.BlacklistEntry{
			MAC:       mac,
			Reason:    reason,
			Comment:   comment,
			CreatedAt: created,
		})
	}
	return entries, rows.Err()
}

// --- Config KV Store ---

// GetConfig retrieves a config value by key.
func (r *SQLiteRepository) GetConfig(ctx context.Context, key string) (string, error) {
	var value string
	err := r.db.QueryRowContext(ctx, `SELECT value FROM config WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}

// SetConfig sets a config key-value pair (insert or replace).
func (r *SQLiteRepository) SetConfig(ctx context.Context, key, value string) error {
	_, err := r.db.ExecContext(ctx, `INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`, key, value)
	return err
}

// --- Helpers ---

func macToString(mac net.HardwareAddr) string {
	if mac == nil {
		return ""
	}
	return strings.ToUpper(mac.String())
}

func buildEventQuery(base string, filter EventFilter) (query string, args []any) {
	var conditions []string

	if !filter.Since.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.Since.Format(time.RFC3339Nano))
	}
	if !filter.Until.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.Until.Format(time.RFC3339Nano))
	}
	if filter.EventType != "" {
		conditions = append(conditions, "event_type = ?")
		args = append(args, filter.EventType)
	}
	if filter.MinSeverity > 0 {
		conditions = append(conditions, "severity >= ?")
		args = append(args, int(filter.MinSeverity))
	}

	query = base
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	return query, args
}

func scanEvent(rows *sql.Rows) (*detector.SecurityEvent, error) {
	var (
		id                                       int64
		tsStr, eventType, description            string
		severity, channel, rssi, frameCount      int
		durationNS                               int64
		srcMAC, dstMAC, bssid, ssid, metadataStr sql.NullString
	)

	err := rows.Scan(&id, &tsStr, &eventType, &severity, &srcMAC, &dstMAC, &bssid, &ssid, &channel, &rssi, &frameCount, &durationNS, &metadataStr, &description)
	if err != nil {
		return nil, err
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid event timestamp %q: %w", tsStr, err)
	}

	ev := &detector.SecurityEvent{
		Timestamp:   ts,
		EventType:   eventType,
		Severity:    detector.Severity(severity),
		Channel:     channel,
		RSSI:        rssi,
		FrameCount:  frameCount,
		Duration:    time.Duration(durationNS),
		Description: description,
		Metadata:    make(map[string]any),
	}

	if srcMAC.Valid && srcMAC.String != "" {
		parsed, err := net.ParseMAC(srcMAC.String)
		if err != nil {
			return nil, fmt.Errorf("storage: invalid event src_mac %q: %w", srcMAC.String, err)
		}
		ev.SrcMAC = parsed
	}
	if dstMAC.Valid && dstMAC.String != "" {
		parsed, err := net.ParseMAC(dstMAC.String)
		if err != nil {
			return nil, fmt.Errorf("storage: invalid event dst_mac %q: %w", dstMAC.String, err)
		}
		ev.DstMAC = parsed
	}
	if bssid.Valid && bssid.String != "" {
		parsed, err := net.ParseMAC(bssid.String)
		if err != nil {
			return nil, fmt.Errorf("storage: invalid event bssid %q: %w", bssid.String, err)
		}
		ev.BSSID = parsed
	}
	if ssid.Valid {
		ev.SSID = ssid.String
	}
	if metadataStr.Valid && metadataStr.String != "" {
		_ = json.Unmarshal([]byte(metadataStr.String), &ev.Metadata)
	}

	return ev, nil
}
