package storage

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/state"
)

func openTestDB(t *testing.T) *SQLiteRepository {
	t.Helper()
	cfg := config.StorageConfig{
		Enabled: true,
		Path:    ":memory:",
	}
	repo, err := Open(cfg)
	if err != nil {
		t.Fatalf("failed to open test DB: %v", err)
	}
	t.Cleanup(func() { repo.Close() })
	return repo
}

func TestOpen_InMemory(t *testing.T) {
	repo := openTestDB(t)
	if repo == nil {
		t.Fatal("expected non-nil repo")
	}
}

func TestSaveAndListEvents(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	srcMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:01")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	event := &detector.SecurityEvent{
		Timestamp:   time.Now(),
		EventType:   "deauth_flood",
		Severity:    detector.SeverityCritical,
		SrcMAC:      srcMAC,
		BSSID:       bssid,
		SSID:        "TestNet",
		Channel:     6,
		RSSI:        -40,
		FrameCount:  50,
		Duration:    5 * time.Second,
		Description: "test event",
		Metadata:    map[string]any{"key": "value"},
	}

	if err := repo.SaveEvent(ctx, event); err != nil {
		t.Fatalf("SaveEvent failed: %v", err)
	}

	events, err := repo.ListEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatalf("ListEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.EventType != "deauth_flood" {
		t.Errorf("expected event type 'deauth_flood', got %q", ev.EventType)
	}
	if ev.Severity != detector.SeverityCritical {
		t.Errorf("expected severity critical, got %v", ev.Severity)
	}
	if ev.SSID != "TestNet" {
		t.Errorf("expected SSID 'TestNet', got %q", ev.SSID)
	}
	if ev.Channel != 6 {
		t.Errorf("expected channel 6, got %d", ev.Channel)
	}
}

func TestListEvents_Filter(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()
	now := time.Now()

	for i := range 5 {
		sev := detector.SeverityInfo
		if i >= 3 {
			sev = detector.SeverityCritical
		}
		ev := &detector.SecurityEvent{
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			EventType: "test",
			Severity:  sev,
			Metadata:  make(map[string]any),
		}
		if err := repo.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	// Filter by severity.
	events, err := repo.ListEvents(ctx, EventFilter{MinSeverity: detector.SeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 critical events, got %d", len(events))
	}

	// Limit.
	events, err = repo.ListEvents(ctx, EventFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events with limit, got %d", len(events))
	}
}

func TestCountEvents(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	for range 3 {
		ev := &detector.SecurityEvent{
			Timestamp: time.Now(),
			EventType: "test",
			Severity:  detector.SeverityInfo,
			Metadata:  make(map[string]any),
		}
		if err := repo.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	count, err := repo.CountEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected 3 events, got %d", count)
	}
}

func TestPruneEvents(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	for i := range 5 {
		ev := &detector.SecurityEvent{
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			EventType: "test",
			Severity:  detector.SeverityInfo,
			Metadata:  make(map[string]any),
		}
		if err := repo.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	pruned, err := repo.PruneEvents(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 2 {
		t.Errorf("expected 2 pruned, got %d", pruned)
	}

	count, _ := repo.CountEvents(ctx, EventFilter{})
	if count != 3 {
		t.Errorf("expected 3 remaining events, got %d", count)
	}
}

func TestSaveAndLatestSnapshot(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond) // truncate for comparison

	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	mac, _ := net.ParseMAC("11:22:33:44:55:66")

	snap := &state.Snapshot{
		Timestamp: now,
		APs:       []*state.APInfo{{BSSID: bssid, SSID: "Net1", Channel: 6}},
		Clients:   []*state.ClientInfo{{MAC: mac, SSID: "Net1", Associated: true}},
	}

	if err := repo.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}

	loaded, err := repo.LatestSnapshot(ctx)
	if err != nil {
		t.Fatalf("LatestSnapshot failed: %v", err)
	}
	if len(loaded.APs) != 1 {
		t.Errorf("expected 1 AP, got %d", len(loaded.APs))
	}
	if len(loaded.Clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(loaded.Clients))
	}
}

func TestPruneSnapshots(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	for i := range 5 {
		snap := &state.Snapshot{
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			APs:       []*state.APInfo{},
			Clients:   []*state.ClientInfo{},
		}
		if err := repo.SaveSnapshot(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}

	pruned, err := repo.PruneSnapshots(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 3 {
		t.Errorf("expected 3 pruned, got %d", pruned)
	}
}

func TestWhitelistCRUD(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")

	entry := &state.WhitelistEntry{
		MAC:       mac,
		SSID:      "TestNet",
		Comment:   "trusted device",
		Source:    "manual",
		CreatedAt: time.Now(),
	}

	if err := repo.SaveWhitelistEntry(ctx, entry); err != nil {
		t.Fatalf("SaveWhitelistEntry failed: %v", err)
	}

	list, err := repo.ListWhitelist(ctx)
	if err != nil {
		t.Fatalf("ListWhitelist failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
	if list[0].Source != "manual" {
		t.Errorf("expected source 'manual', got %q", list[0].Source)
	}

	if err := repo.DeleteWhitelistEntry(ctx, mac.String()); err != nil {
		t.Fatalf("DeleteWhitelistEntry failed: %v", err)
	}
	list, _ = repo.ListWhitelist(ctx)
	if len(list) != 0 {
		t.Errorf("expected 0 entries after delete, got %d", len(list))
	}
}

func TestBlacklistCRUD(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	entry := &state.BlacklistEntry{
		MAC:       mac,
		Reason:    "attacker",
		Comment:   "deauth flooding",
		CreatedAt: time.Now(),
	}

	if err := repo.SaveBlacklistEntry(ctx, entry); err != nil {
		t.Fatalf("SaveBlacklistEntry failed: %v", err)
	}

	list, err := repo.ListBlacklist(ctx)
	if err != nil {
		t.Fatalf("ListBlacklist failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}

	if err := repo.DeleteBlacklistEntry(ctx, mac.String()); err != nil {
		t.Fatal(err)
	}
	list, _ = repo.ListBlacklist(ctx)
	if len(list) != 0 {
		t.Errorf("expected 0 entries after delete, got %d", len(list))
	}
}

func TestConfigKV(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	if err := repo.SetConfig(ctx, "learning_state", "completed"); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}

	val, err := repo.GetConfig(ctx, "learning_state")
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if val != "completed" {
		t.Errorf("expected 'completed', got %q", val)
	}

	// Non-existent key.
	_, err = repo.GetConfig(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestMigration_Idempotent(t *testing.T) {
	// Opening twice should not fail (schema already exists).
	cfg := config.StorageConfig{Enabled: true, Path: ":memory:"}
	repo, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Manually call migrate again.
	if err := migrate(context.Background(), repo.db); err != nil {
		t.Fatalf("second migration failed: %v", err)
	}
	repo.Close()
}

// TestOpen_OnDiskPermissions verifies that an on-disk SQLite database is
// created (or chmod-ed) with mode 0600 to protect captured security data.
func TestOpen_OnDiskPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.db")
	repo, err := Open(config.StorageConfig{Enabled: true, Path: path})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("expected DB file mode 0600, got %#o", got)
	}
}

// TestLatestSnapshot_InvalidTimestamp ensures parse errors on a corrupted
// timestamp surface to the caller instead of being silently dropped.
func TestLatestSnapshot_InvalidTimestamp(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	// Insert a row with an invalid RFC3339 timestamp directly.
	_, err := repo.db.ExecContext(ctx,
		`INSERT INTO snapshots (timestamp, aps_json, clients_json) VALUES (?, ?, ?)`,
		"not-a-timestamp", "[]", "[]",
	)
	if err != nil {
		t.Fatalf("setup insert failed: %v", err)
	}

	if _, err := repo.LatestSnapshot(ctx); err == nil {
		t.Fatal("expected error for invalid timestamp, got nil")
	}
}

// TestListWhitelist_InvalidMAC ensures parse errors on a corrupted MAC
// surface to the caller instead of being silently dropped.
func TestListWhitelist_InvalidMAC(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	_, err := repo.db.ExecContext(ctx,
		`INSERT INTO whitelist (mac, ssid, comment, source, created_at) VALUES (?, ?, ?, ?, ?)`,
		"not-a-mac", "", "", "manual", time.Now().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("setup insert failed: %v", err)
	}

	if _, err := repo.ListWhitelist(ctx); err == nil {
		t.Fatal("expected error for invalid MAC, got nil")
	}
}

// TestSessionsCRUD covers create / get / delete / prune for the v2 sessions
// table introduced in Phase 4.
func TestSessionsCRUD(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	sess := &Session{
		Token:     "test-token-abc",
		Role:      SessionRoleAdmin,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repo.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	loaded, err := repo.GetSession(ctx, sess.Token)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if loaded.Role != SessionRoleAdmin {
		t.Errorf("expected role admin, got %q", loaded.Role)
	}
	if !loaded.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Errorf("expires_at round-trip mismatch: got %v want %v", loaded.ExpiresAt, sess.ExpiresAt)
	}

	if _, err := repo.GetSession(ctx, "missing"); err == nil {
		t.Error("expected ErrNotFound for missing token")
	}

	if err := repo.DeleteSession(ctx, sess.Token); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	if _, err := repo.GetSession(ctx, sess.Token); err == nil {
		t.Error("expected error after deletion")
	}
}

func TestSaveEvent_Nil(t *testing.T) {
	repo := openTestDB(t)
	if err := repo.SaveEvent(t.Context(), nil); err != nil {
		t.Errorf("SaveEvent(nil) should return nil, got %v", err)
	}
}

func TestSaveSnapshot_Nil(t *testing.T) {
	repo := openTestDB(t)
	if err := repo.SaveSnapshot(t.Context(), nil); err != nil {
		t.Errorf("SaveSnapshot(nil) should return nil, got %v", err)
	}
}

func TestLatestSnapshot_NotFound(t *testing.T) {
	repo := openTestDB(t)
	_, err := repo.LatestSnapshot(t.Context())
	if err == nil {
		t.Fatal("expected ErrNotFound for empty snapshots table")
	}
}

func TestSaveWhitelistEntry_Nil(t *testing.T) {
	repo := openTestDB(t)
	if err := repo.SaveWhitelistEntry(t.Context(), nil); err != nil {
		t.Errorf("SaveWhitelistEntry(nil) should return nil, got %v", err)
	}
	// Nil MAC.
	entry := &state.WhitelistEntry{MAC: nil, Source: "manual", CreatedAt: time.Now()}
	if err := repo.SaveWhitelistEntry(t.Context(), entry); err != nil {
		t.Errorf("SaveWhitelistEntry(nil MAC) should return nil, got %v", err)
	}
}

func TestSaveBlacklistEntry_Nil(t *testing.T) {
	repo := openTestDB(t)
	if err := repo.SaveBlacklistEntry(t.Context(), nil); err != nil {
		t.Errorf("SaveBlacklistEntry(nil) should return nil, got %v", err)
	}
	entry := &state.BlacklistEntry{MAC: nil, Reason: "test", CreatedAt: time.Now()}
	if err := repo.SaveBlacklistEntry(t.Context(), entry); err != nil {
		t.Errorf("SaveBlacklistEntry(nil MAC) should return nil, got %v", err)
	}
}

func TestCreateSession_Invalid(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	if err := repo.CreateSession(ctx, nil); err == nil {
		t.Error("CreateSession(nil) should return error")
	}
	if err := repo.CreateSession(ctx, &Session{Token: ""}); err == nil {
		t.Error("CreateSession(empty token) should return error")
	}
}

func TestListEvents_Until(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	now := time.Now()
	for i := range 3 {
		ev := &detector.SecurityEvent{
			Timestamp: now.Add(-time.Duration(3-i) * time.Hour),
			EventType: "test",
			Severity:  detector.SeverityInfo,
			Metadata:  make(map[string]any),
		}
		if err := repo.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	// Until filters to events with timestamp <= cutoff.
	// Events at -3h, -2h, -1h; cutoff at -2h → only -3h and -2h match.
	events, err := repo.ListEvents(ctx, EventFilter{Until: now.Add(-2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events with Until=-2h, got %d", len(events))
	}
}

func TestListBlacklist_InvalidMAC(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	_, err := repo.db.ExecContext(ctx,
		`INSERT INTO blacklist (mac, reason, comment, created_at) VALUES (?, ?, ?, ?)`,
		"not-a-mac", "", "", time.Now().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ListBlacklist(ctx); err == nil {
		t.Error("expected error for invalid MAC in blacklist")
	}
}

func TestGetSession_InvalidTimestamps(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	// Insert a session with invalid created_at.
	_, err := repo.db.ExecContext(ctx,
		`INSERT INTO sessions (token, role, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		"bad-created", "admin", "not-a-timestamp", time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetSession(ctx, "bad-created"); err == nil {
		t.Error("expected error for invalid created_at in session")
	}
}

func TestMigration_V2(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	// Fake an older schema version so migrate applies v2.
	_, err := repo.db.ExecContext(ctx, "UPDATE schema_version SET version = 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, repo.db); err != nil {
		t.Fatalf("v2 migration failed: %v", err)
	}
	// Query the sessions table to verify it exists.
	var count int
	if err := repo.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='sessions'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Error("sessions table should exist after v2 migration")
	}
}

func TestPruneEvents_Zero(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	for i := range 3 {
		ev := &detector.SecurityEvent{
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			EventType: "test",
			Severity:  detector.SeverityInfo,
			Metadata:  make(map[string]any),
		}
		if err := repo.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	pruned, err := repo.PruneEvents(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 3 {
		t.Errorf("expected 3 pruned with maxCount=0, got %d", pruned)
	}
}

func TestPruneExpiredSessions(t *testing.T) {
	repo := openTestDB(t)
	ctx := context.Background()
	now := time.Now()

	active := &Session{Token: "active", Role: SessionRoleUser, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	expired := &Session{Token: "expired", Role: SessionRoleUser, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := repo.CreateSession(ctx, active); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, expired); err != nil {
		t.Fatal(err)
	}

	removed, err := repo.PruneExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpiredSessions failed: %v", err)
	}
	if removed != 1 {
		t.Errorf("expected 1 expired session removed, got %d", removed)
	}
	if _, err := repo.GetSession(ctx, "active"); err != nil {
		t.Errorf("active session should remain: %v", err)
	}
	if _, err := repo.GetSession(ctx, "expired"); err == nil {
		t.Error("expired session should have been removed")
	}
}

func TestListEvents_Offset(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	for i := range 5 {
		ev := &detector.SecurityEvent{
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			EventType: "test",
			Severity:  detector.SeverityInfo,
			Metadata:  make(map[string]any),
		}
		if err := repo.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	// Offset should skip first 2 events.
	events, err := repo.ListEvents(ctx, EventFilter{Limit: 10, Offset: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events with offset=2, got %d", len(events))
	}
}

func TestListEvents_EventType(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	for i := range 2 {
		ev := &detector.SecurityEvent{
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			EventType: "deauth_flood",
			Severity:  detector.SeverityCritical,
			Metadata:  make(map[string]any),
		}
		if err := repo.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	// Add one event of a different type.
	ev := &detector.SecurityEvent{
		Timestamp: time.Now(),
		EventType: "evil_twin",
		Severity:  detector.SeverityWarning,
		Metadata:  make(map[string]any),
	}
	if err := repo.SaveEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	events, err := repo.ListEvents(ctx, EventFilter{EventType: "deauth_flood"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 deauth_flood events, got %d", len(events))
	}
}

func TestListEvents_Since(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	now := time.Now()
	ev := &detector.SecurityEvent{
		Timestamp: now.Add(-time.Hour),
		EventType: "test",
		Severity:  detector.SeverityInfo,
		Metadata:  make(map[string]any),
	}
	if err := repo.SaveEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	events, err := repo.ListEvents(ctx, EventFilter{Since: now.Add(-30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	// Event is more than 30 minutes old, should be filtered out.
	if len(events) != 0 {
		t.Errorf("expected 0 events with Since filter, got %d", len(events))
	}
}

func TestListEvents_NoResults(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	events, err := repo.ListEvents(ctx, EventFilter{EventType: "nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestSaveEvent_NilMetadata(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	ev := &detector.SecurityEvent{
		Timestamp: time.Now(),
		EventType: "test",
		Severity:  detector.SeverityInfo,
		Metadata:  nil,
	}
	if err := repo.SaveEvent(ctx, ev); err != nil {
		t.Errorf("SaveEvent(nil metadata) should succeed, got %v", err)
	}
}

func TestIsMemoryDSN(t *testing.T) {
	if !isMemoryDSN(":memory:") {
		t.Error(":memory: should be detected")
	}
	if !isMemoryDSN("file::memory:?cache=shared") {
		t.Error("file::memory: DSN should be detected")
	}
	if !isMemoryDSN("file:test?mode=memory") {
		t.Error("mode=memory DSN should be detected")
	}
	if isMemoryDSN("real/path.db") {
		t.Error("real path should not be detected as memory")
	}
}

func TestGetSession_InvalidExpiresAt(t *testing.T) {
	repo := openTestDB(t)
	ctx := t.Context()
	_, err := repo.db.ExecContext(ctx,
		`INSERT INTO sessions (token, role, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		"bad-expires", "admin", time.Now().Format(time.RFC3339Nano), "not-a-timestamp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetSession(ctx, "bad-expires"); err == nil {
		t.Error("expected error for invalid expires_at in session")
	}
}
