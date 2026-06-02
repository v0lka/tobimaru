package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReaderValidConfig(t *testing.T) {
	yaml := `
log:
  level: debug
  format: json
monitor:
  interface: wlan0
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("expected log level debug, got %q", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("expected log format json, got %q", cfg.Log.Format)
	}
	if cfg.Monitor.Interface != "wlan0" {
		t.Errorf("expected monitor interface wlan0, got %q", cfg.Monitor.Interface)
	}
	if cfg.Monitor.Capture.Snaplen != DefaultSnaplen {
		t.Errorf("expected snaplen %d, got %d", DefaultSnaplen, cfg.Monitor.Capture.Snaplen)
	}
	if cfg.Monitor.ChannelHopping.Dwell != DefaultDwellTime {
		t.Errorf("expected dwell %v, got %v", DefaultDwellTime, cfg.Monitor.ChannelHopping.Dwell)
	}
}

func TestLoadReaderDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("expected default log level info, got %q", cfg.Log.Level)
	}
	if cfg.Log.Format != "text" {
		t.Errorf("expected default log format text, got %q", cfg.Log.Format)
	}
}

func TestLoadReaderMissingInterface(t *testing.T) {
	yaml := `
log:
  level: info
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("expected error for missing interface, got nil")
	}
	if !IsValidationError(err) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestLoadReaderInvalidLogLevel(t *testing.T) {
	yaml := `
log:
  level: fatal
monitor:
  interface: wlan0
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("expected error for invalid log level, got nil")
	}
	if !IsValidationError(err) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestLoadReaderInvalidLogFormat(t *testing.T) {
	yaml := `
log:
  format: xml
monitor:
  interface: wlan0
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("expected error for invalid log format, got nil")
	}
	if !IsValidationError(err) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestLoadReaderUnknownField(t *testing.T) {
	yaml := `
log:
  level: info
monitor:
  interface: wlan0
  unknown_field: value
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestValidationError(t *testing.T) {
	yaml := `
log:
  level: fatal
  format: xml
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if len(ve.Errors) < 3 {
		t.Errorf("expected at least 3 errors (missing interface, invalid level, invalid format), got %d", len(ve.Errors))
	}
}

func TestChannelHoppingDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
  channel_hopping:
    enabled: true
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Monitor.ChannelHopping.Enabled {
		t.Error("expected channel hopping enabled")
	}
	if cfg.Monitor.ChannelHopping.Dwell != DefaultDwellTime {
		t.Errorf("expected dwell %v, got %v", DefaultDwellTime, cfg.Monitor.ChannelHopping.Dwell)
	}
	if len(cfg.Monitor.ChannelHopping.Channels2GHz) != 13 {
		t.Errorf("expected 13 2.4 GHz channels, got %d", len(cfg.Monitor.ChannelHopping.Channels2GHz))
	}
	if len(cfg.Monitor.ChannelHopping.Channels5GHz) == 0 {
		t.Error("expected non-empty 5 GHz channels")
	}
}

func TestCaptureConfigDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Monitor.Capture.Snaplen != DefaultSnaplen {
		t.Errorf("expected snaplen %d, got %d", DefaultSnaplen, cfg.Monitor.Capture.Snaplen)
	}
	if cfg.Monitor.Capture.BufferSize != DefaultBufferSize {
		t.Errorf("expected buffer_size %d, got %d", DefaultBufferSize, cfg.Monitor.Capture.BufferSize)
	}
	if cfg.Monitor.Capture.FrameBufferSize != DefaultFrameBufferSize {
		t.Errorf("expected frame_buffer_size %d, got %d", DefaultFrameBufferSize, cfg.Monitor.Capture.FrameBufferSize)
	}
}

func TestZeroDwellTimeUsesDefault(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
  channel_hopping:
    enabled: true
    dwell: 0ms
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Zero dwell should be replaced with default.
	if cfg.Monitor.ChannelHopping.Dwell != DefaultDwellTime {
		t.Errorf("expected default dwell %v, got %v", DefaultDwellTime, cfg.Monitor.ChannelHopping.Dwell)
	}
}

func TestDetectionDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Detection.DedupWindow != DefaultDedupWindow {
		t.Errorf("expected dedup_window %v, got %v", DefaultDedupWindow, cfg.Detection.DedupWindow)
	}
	if cfg.Detection.AlertBufferSize != DefaultAlertBufferSize {
		t.Errorf("expected alert_buffer_size %d, got %d", DefaultAlertBufferSize, cfg.Detection.AlertBufferSize)
	}
	// Enabled defaults to false via zero value.
	if cfg.Detection.Enabled {
		t.Error("expected detection to be disabled by default")
	}
}

func TestDetectionCustomValues(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
detection:
  enabled: true
  dedup_window: 10s
  alert_buffer_size: 512
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Detection.Enabled {
		t.Error("expected detection enabled")
	}
	if cfg.Detection.DedupWindow != 10*1000*1000*1000 { // 10s in nanoseconds
		t.Errorf("expected dedup_window 10s, got %v", cfg.Detection.DedupWindow)
	}
	if cfg.Detection.AlertBufferSize != 512 {
		t.Errorf("expected alert_buffer_size 512, got %d", cfg.Detection.AlertBufferSize)
	}
}

func TestDetectionZeroValuesGetDefaults(t *testing.T) {
	// When detection is enabled but dedup_window and alert_buffer_size are zero,
	// defaults should fill them (defaults run before validation).
	yaml := `
monitor:
  interface: wlan0
detection:
  enabled: true
  dedup_window: 0s
  alert_buffer_size: 0
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Detection.DedupWindow != DefaultDedupWindow {
		t.Errorf("expected dedup_window %v, got %v", DefaultDedupWindow, cfg.Detection.DedupWindow)
	}
	if cfg.Detection.AlertBufferSize != DefaultAlertBufferSize {
		t.Errorf("expected alert_buffer_size %d, got %d", DefaultAlertBufferSize, cfg.Detection.AlertBufferSize)
	}
}

func TestDetectionDisabledSkipsValidation(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
detection:
  enabled: false
  dedup_window: 0s
  alert_buffer_size: 0
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error when detection disabled: %v", err)
	}
	if cfg.Detection.Enabled {
		t.Error("expected detection disabled")
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
monitor:
  interface: wlan0
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Monitor.Interface != "wlan0" {
		t.Errorf("expected interface wlan0, got %q", cfg.Monitor.Interface)
	}
}

func TestLoadFromFileMissing(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFromFileInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml: {{"), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidationErrorString(t *testing.T) {
	ve := &ValidationError{
		Errors: []error{ErrMissingInterface, ErrInvalidLogLevel},
	}
	s := ve.Error()
	if !strings.Contains(s, "validation failed") {
		t.Errorf("expected 'validation failed' in error string, got %q", s)
	}
	if !strings.Contains(s, "interface") {
		t.Errorf("expected 'interface' in error string, got %q", s)
	}
}
