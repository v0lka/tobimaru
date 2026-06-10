package state

import (
	"context"
	"log/slog"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
)

// LearningMode manages the auto-learning phase where all observed devices
// are automatically added to the whitelist after the learning timer expires.
type LearningMode struct {
	cfg    config.AutoLearningConfig
	engine *Engine
	logger *slog.Logger
	active bool
}

// NewLearningMode creates a new auto-learning controller.
func NewLearningMode(cfg config.AutoLearningConfig, engine *Engine, logger *slog.Logger) *LearningMode {
	return &LearningMode{
		cfg:    cfg,
		engine: engine,
		logger: logger,
	}
}

// IsActive returns whether learning mode is currently active.
func (l *LearningMode) IsActive() bool {
	return l.active
}

// Run starts the learning phase. It observes the state engine for the
// configured duration, then builds a whitelist from all observed associated
// clients. Exits on ctx cancellation or when the timer expires.
// Returns the generated whitelist entries.
func (l *LearningMode) Run(ctx context.Context) []*WhitelistEntry {
	l.active = true
	l.logger.Info("auto-learning mode started",
		"duration", l.cfg.Duration,
	)

	timer := time.NewTimer(l.cfg.Duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		l.active = false
		l.logger.Info("auto-learning mode canceled")
		return nil
	case <-timer.C:
		// Learning phase complete — build whitelist from observed clients.
	}

	entries := l.buildWhitelist()
	l.active = false

	l.logger.Info("auto-learning mode complete",
		"entries_generated", len(entries),
	)

	// Apply to the in-memory whitelist engine.
	l.engine.Whitelist().BulkAddWhitelist(entries)

	return entries
}

// buildWhitelist generates whitelist entries from currently observed associated clients.
func (l *LearningMode) buildWhitelist() []*WhitelistEntry {
	clients := l.engine.Clients().All()
	now := time.Now()

	var entries []*WhitelistEntry
	for _, client := range clients {
		if !client.Associated {
			continue
		}
		entry := &WhitelistEntry{
			MAC:       client.MAC,
			SSID:      client.SSID,
			Comment:   "auto-learned during learning phase",
			Source:    WhitelistSourceAutoLearning,
			CreatedAt: now,
		}
		entries = append(entries, entry)
	}
	return entries
}
