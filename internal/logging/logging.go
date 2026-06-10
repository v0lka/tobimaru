// Package logging provides slog logger initialization from configuration.
package logging

import (
	"log/slog"
	"os"

	"github.com/vkochetkov/tobimaru/internal/config"
)

// levelVar is the package-level atomic slog.LevelVar that backs every logger
// created by New. Components that allow runtime log-level changes (e.g. the
// HTTP API's PUT /api/config endpoint) call SetLevel to adjust verbosity
// without recreating the logger.
var levelVar = new(slog.LevelVar)

// New creates a new slog.Logger based on the provided logging configuration.
// It maps log level and format strings to the corresponding slog settings,
// and writes output to stdout. The returned logger shares the package-level
// LevelVar, so subsequent calls to SetLevel affect all loggers built here.
func New(cfg config.LogConfig) *slog.Logger {
	levelVar.Set(parseLevel(cfg.Level))
	opts := &slog.HandlerOptions{Level: levelVar}

	var handler slog.Handler
	if cfg.Format == config.LogFormatJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// SetLevel updates the runtime log level used by all loggers created via New.
// It accepts the same string values as the YAML config (debug, info, warn,
// error). Unknown values are ignored.
func SetLevel(s string) bool {
	switch s {
	case config.LogLevelDebug:
		levelVar.Set(slog.LevelDebug)
	case config.LogLevelInfo:
		levelVar.Set(slog.LevelInfo)
	case config.LogLevelWarn:
		levelVar.Set(slog.LevelWarn)
	case config.LogLevelError:
		levelVar.Set(slog.LevelError)
	default:
		return false
	}
	return true
}

// Level returns the current effective log level as a string.
func Level() string {
	switch levelVar.Level() {
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
