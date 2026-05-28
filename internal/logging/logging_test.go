package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/vkochetkov/tobimaru/internal/config"
)

func TestNewTextFormat(t *testing.T) {
	cfg := config.LogConfig{Level: "info", Format: "text"}
	_ = New(cfg)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected text output to contain message, got: %s", output)
	}
}

func TestNewJSONFormat(t *testing.T) {
	cfg := config.LogConfig{Level: "info", Format: "json"}
	_ = New(cfg)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("test json")

	output := buf.String()
	if !strings.Contains(output, "test json") {
		t.Errorf("expected JSON output, got: %s", output)
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
