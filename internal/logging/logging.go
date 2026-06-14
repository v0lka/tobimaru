// Package logging provides slog logger initialization from configuration.
package logging

import (
	"log/slog"
	"os"

	"github.com/vkochetkov/tobimaru/internal/config"
)

// LevelControl manages runtime log-level changes for a logger created by
// New. Each LevelControl owns a single slog.LevelVar; calling Set changes
// the level of every handler that shares the same LevelVar, without
// recreating the logger.
type LevelControl struct {
	lv *slog.LevelVar
}

// New creates a new slog.Logger based on the provided logging configuration.
// It maps log level and format strings to the corresponding slog settings,
// and writes output to stdout. The returned LevelControl allows runtime
// level changes via its Set method — each logger gets its own LevelControl,
// so independent loggers do not interfere with each other.
func New(cfg config.LogConfig) (*slog.Logger, *LevelControl) {
	lc := &LevelControl{lv: new(slog.LevelVar)}
	lc.lv.Set(parseLevel(cfg.Level))
	opts := &slog.HandlerOptions{Level: lc.lv}

	var handler slog.Handler
	if cfg.Format == config.LogFormatJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler), lc
}

// NewLevelControl creates a LevelControl initialized to the given level.
// It is useful when callers need a LevelControl without creating a full
// logger (e.g. in tests or when wiring dependencies before the logger
// is constructed).
func NewLevelControl(level string) *LevelControl {
	lc := &LevelControl{lv: new(slog.LevelVar)}
	lc.lv.Set(parseLevel(level))
	return lc
}

// Set updates the runtime log level. It accepts the same string values as
// the YAML config (debug, info, warn, error). Unknown values are ignored;
// the return value reports whether the level was recognized.
func (lc *LevelControl) Set(s string) bool {
	switch s {
	case config.LogLevelDebug:
		lc.lv.Set(slog.LevelDebug)
	case config.LogLevelInfo:
		lc.lv.Set(slog.LevelInfo)
	case config.LogLevelWarn:
		lc.lv.Set(slog.LevelWarn)
	case config.LogLevelError:
		lc.lv.Set(slog.LevelError)
	default:
		return false
	}
	return true
}

// Level returns the current effective log level as a string.
func (lc *LevelControl) Level() string {
	switch lc.lv.Level() {
	case slog.LevelDebug:
		return config.LogLevelDebug
	case slog.LevelWarn:
		return config.LogLevelWarn
	case slog.LevelError:
		return config.LogLevelError
	default:
		return config.LogLevelInfo
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case config.LogLevelDebug:
		return slog.LevelDebug
	case config.LogLevelInfo:
		return slog.LevelInfo
	case config.LogLevelWarn:
		return slog.LevelWarn
	case config.LogLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
