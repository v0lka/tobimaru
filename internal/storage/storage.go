// Package storage provides the persistence layer for Tobimaru, including
// security event storage, state snapshots, and whitelist/blacklist management.
package storage

import (
	"context"
	"time"

	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/state"
)

// Repository defines the persistence interface for Tobimaru.
// All methods are context-aware for timeout/cancellation support.
type Repository interface {
	// Close closes the underlying storage connection.
	Close() error

	// Security Events
	SaveEvent(ctx context.Context, event *detector.SecurityEvent) error
	ListEvents(ctx context.Context, filter EventFilter) ([]*detector.SecurityEvent, error)
	CountEvents(ctx context.Context, filter EventFilter) (int64, error)
	PruneEvents(ctx context.Context, maxCount int) (int64, error)

	// State Snapshots
	SaveSnapshot(ctx context.Context, snap *state.Snapshot) error
	LatestSnapshot(ctx context.Context) (*state.Snapshot, error)
	PruneSnapshots(ctx context.Context, maxCount int) (int64, error)

	// Whitelist
	SaveWhitelistEntry(ctx context.Context, entry *state.WhitelistEntry) error
	DeleteWhitelistEntry(ctx context.Context, mac string) error
	ListWhitelist(ctx context.Context) ([]*state.WhitelistEntry, error)

	// Blacklist
	SaveBlacklistEntry(ctx context.Context, entry *state.BlacklistEntry) error
	DeleteBlacklistEntry(ctx context.Context, mac string) error
	ListBlacklist(ctx context.Context) ([]*state.BlacklistEntry, error)

	// Configuration key-value store
	GetConfig(ctx context.Context, key string) (string, error)
	SetConfig(ctx context.Context, key, value string) error
}

// EventFilter defines criteria for querying security events.
type EventFilter struct {
	Since       time.Time
	Until       time.Time
	EventType   string
	MinSeverity detector.Severity
	Limit       int
	Offset      int
}
