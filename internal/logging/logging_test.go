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
		t.Errorf("got %v, want LevelDebug", l)
	}
}

func TestParseLevelInfo(t *testing.T) {
	if l := parseLevel("info"); l != slog.LevelInfo {
		t.Errorf("got %v, want LevelInfo", l)
	}
}

func TestParseLevelWarn(t *testing.T) {
	if l := parseLevel("warn"); l != slog.LevelWarn {
		t.Errorf("got %v, want LevelWarn", l)
	}
}

func TestParseLevelError(t *testing.T) {
	if l := parseLevel("error"); l != slog.LevelError {
		t.Errorf("got %v, want LevelError", l)
	}
}

func TestParseLevelUnknown(t *testing.T) {
	if l := parseLevel("fatal"); l != slog.LevelInfo {
		t.Errorf("got %v, want fallback to LevelInfo", l)
	}
}

func TestSetLevel_AllLevels(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{"debug", config.LogLevelDebug, slog.LevelDebug},
		{"info", config.LogLevelInfo, slog.LevelInfo},
		{"warn", config.LogLevelWarn, slog.LevelWarn},
		{"error", config.LogLevelError, slog.LevelError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok := SetLevel(tt.input)
			if !ok {
				t.Error("SetLevel returned false for valid level")
			}
			if got := levelVar.Level(); got != tt.want {
				t.Errorf("levelVar.Level() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetLevel_Unknown(t *testing.T) {
	if SetLevel("verbose") {
		t.Error("SetLevel should return false for unknown level")
	}
}

func TestLevel_ReturnsString(t *testing.T) {
	tests := []struct {
		set  string
		want string
	}{
		{config.LogLevelDebug, config.LogLevelDebug},
		{config.LogLevelInfo, config.LogLevelInfo},
		{config.LogLevelWarn, config.LogLevelWarn},
		{config.LogLevelError, config.LogLevelError},
	}
	for _, tt := range tests {
		t.Run(tt.set, func(t *testing.T) {
			SetLevel(tt.set)
			if got := Level(); got != tt.want {
				t.Errorf("Level() = %q, want %q", got, tt.want)
			}
		})
	}
}
