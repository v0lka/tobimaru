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
		t.Errorf("got log level %q, want debug", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("got log format %q, want json", cfg.Log.Format)
	}
	if cfg.Monitor.Interface != "wlan0" {
		t.Errorf("got monitor interface %q, want wlan0", cfg.Monitor.Interface)
	}
	if cfg.Monitor.Capture.Snaplen != DefaultSnaplen {
		t.Errorf("got snaplen %d, want %d", cfg.Monitor.Capture.Snaplen, DefaultSnaplen)
	}
	if cfg.Monitor.ChannelHopping.Dwell != DefaultDwellTime {
		t.Errorf("got dwell %v, want %v", cfg.Monitor.ChannelHopping.Dwell, DefaultDwellTime)
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
		t.Errorf("got default log level %q, want info", cfg.Log.Level)
	}
	if cfg.Log.Format != "text" {
		t.Errorf("got default log format %q, want text", cfg.Log.Format)
	}
}

func TestLoadReaderMissingInterface(t *testing.T) {
	yaml := `
log:
  level: info
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("got nil, want error for missing interface")
	}
	if !IsValidationError(err) {
		t.Fatalf("got %T: %v, want ValidationError", err, err)
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
		t.Fatal("got nil, want error for invalid log level")
	}
	if !IsValidationError(err) {
		t.Fatalf("got %T: %v, want ValidationError", err, err)
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
		t.Fatal("got nil, want error for invalid log format")
	}
	if !IsValidationError(err) {
		t.Fatalf("got %T: %v, want ValidationError", err, err)
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
		t.Fatal("got nil, want error for unknown field")
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
		t.Fatal("got nil, want error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("got %T: %v, want *ValidationError", err, err)
	}
	if len(ve.Errors) < 3 {
		t.Errorf("got %d errors, want at least 3 (missing interface, invalid level, invalid format)", len(ve.Errors))
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
		t.Errorf("got dwell %v, want %v", cfg.Monitor.ChannelHopping.Dwell, DefaultDwellTime)
	}
	if len(cfg.Monitor.ChannelHopping.Channels2GHz) != 13 {
		t.Errorf("got %d 2.4 GHz channels, want 13", len(cfg.Monitor.ChannelHopping.Channels2GHz))
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
		t.Errorf("got snaplen %d, want %d", cfg.Monitor.Capture.Snaplen, DefaultSnaplen)
	}
	if cfg.Monitor.Capture.BufferSize != DefaultBufferSize {
		t.Errorf("got buffer_size %d, want %d", cfg.Monitor.Capture.BufferSize, DefaultBufferSize)
	}
	if cfg.Monitor.Capture.FrameBufferSize != DefaultFrameBufferSize {
		t.Errorf("got frame_buffer_size %d, want %d", cfg.Monitor.Capture.FrameBufferSize, DefaultFrameBufferSize)
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
		t.Errorf("got default dwell %v, want %v", cfg.Monitor.ChannelHopping.Dwell, DefaultDwellTime)
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
		t.Errorf("got dedup_window %v, want %v", cfg.Detection.DedupWindow, DefaultDedupWindow)
	}
	if cfg.Detection.AlertBufferSize != DefaultAlertBufferSize {
		t.Errorf("got alert_buffer_size %d, want %d", cfg.Detection.AlertBufferSize, DefaultAlertBufferSize)
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
		t.Errorf("got dedup_window %v, want 10s", cfg.Detection.DedupWindow)
	}
	if cfg.Detection.AlertBufferSize != 512 {
		t.Errorf("got alert_buffer_size %d, want 512", cfg.Detection.AlertBufferSize)
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
		t.Errorf("got dedup_window %v, want %v", cfg.Detection.DedupWindow, DefaultDedupWindow)
	}
	if cfg.Detection.AlertBufferSize != DefaultAlertBufferSize {
		t.Errorf("got alert_buffer_size %d, want %d", cfg.Detection.AlertBufferSize, DefaultAlertBufferSize)
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
		t.Errorf("got interface %q, want wlan0", cfg.Monitor.Interface)
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
		t.Errorf("got %q, want 'validation failed' in error string", s)
	}
	if !strings.Contains(s, "interface") {
		t.Errorf("got %q, want 'interface' in error string", s)
	}
}
