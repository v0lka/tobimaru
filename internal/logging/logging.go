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
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// Log level string constants used in configuration.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

func parseLevel(s string) slog.Level {
	switch s {
	case LevelDebug:
		return slog.LevelDebug
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
