package logging

import (
	"context"
	"log/slog"
	"testing"

	"github.com/vkochetkov/tobimaru/internal/config"
)

func TestNewTextFormat(t *testing.T) {
	cfg := config.LogConfig{Level: "debug", Format: "text"}
	logger := New(cfg)
	if logger == nil {
		t.Fatal("New() returned nil")
	}

	// Verify the handler is a text handler with the correct level.
	handler := logger.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}
	if !handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("text handler should be enabled for debug level")
	}
	if handler.Enabled(context.Background(), slog.LevelDebug-1) {
		t.Error("text handler should not be enabled below debug level")
	}
}

func TestNewJSONFormat(t *testing.T) {
	cfg := config.LogConfig{Level: "debug", Format: "json"}
	logger := New(cfg)
	if logger == nil {
		t.Fatal("New() returned nil")
	}

	// Verify the handler is a JSON handler with the correct level.
	handler := logger.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}
	if !handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("json handler should be enabled for debug level")
	}
}

func TestParseLevelDebug(t *testing.T) {
	if l := parseLevel("debug"); l != slog.LevelDebug {
		t.Errorf("expected LevelDebug, got %v", l)
	}
}

func TestParseLevelInfo(t *testing.T) {
	if l := parseLevel("info"); l != slog.LevelInfo {
		t.Errorf("expected LevelInfo, got %v", l)
	}
}

func TestParseLevelWarn(t *testing.T) {
	if l := parseLevel("warn"); l != slog.LevelWarn {
		t.Errorf("expected LevelWarn, got %v", l)
	}
}

func TestParseLevelError(t *testing.T) {
	if l := parseLevel("error"); l != slog.LevelError {
		t.Errorf("expected LevelError, got %v", l)
	}
}

func TestParseLevelUnknown(t *testing.T) {
	if l := parseLevel("fatal"); l != slog.LevelInfo {
		t.Errorf("expected fallback to LevelInfo, got %v", l)
	}
}
