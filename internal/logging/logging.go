// Package logging provides slog logger initialization from configuration.
package logging

import (
	"log/slog"
	"os"

	"github.com/vkochetkov/tobimaru/internal/config"
)

// New creates a new slog.Logger based on the provided logging configuration.
// It maps log level and format strings to the corresponding slog settings,
// and writes output to stdout.
func New(cfg config.LogConfig) *slog.Logger {
	level := parseLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Format == config.LogFormatJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
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
