package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	// Channel lists are not populated at config-load time — they are
	// auto-detected from hardware at pipeline creation (nil = "auto").
	if cfg.Monitor.ChannelHopping.Channels2GHz != nil {
		t.Errorf("expected nil Channels2GHz (auto-detect), got %v", cfg.Monitor.ChannelHopping.Channels2GHz)
	}
	if cfg.Monitor.ChannelHopping.Channels5GHz != nil {
		t.Errorf("expected nil Channels5GHz (auto-detect), got %v", cfg.Monitor.ChannelHopping.Channels5GHz)
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

func TestStateDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
state:
  enabled: true
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.State.TTL != DefaultStateTTL {
		t.Errorf("got state.ttl %v, want %v", cfg.State.TTL, DefaultStateTTL)
	}
	if cfg.State.SweepInterval != DefaultStateSweepInterval {
		t.Errorf("got state.sweep_interval %v, want %v", cfg.State.SweepInterval, DefaultStateSweepInterval)
	}
}

func TestStateZeroValuesGetDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
state:
  enabled: true
  ttl: 0s
  sweep_interval: 0s
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.State.TTL != DefaultStateTTL {
		t.Errorf("got state.ttl %v, want default %v", cfg.State.TTL, DefaultStateTTL)
	}
}

func TestStateNegativeTTLValidation(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
state:
  enabled: true
  ttl: -1s
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("got nil, want validation error for negative state.ttl")
	}
	if !errors.Is(err, ErrInvalidStateTTL) {
		t.Errorf("got %v, want ErrInvalidStateTTL", err)
	}
}

func TestStateNegativeSweepIntervalValidation(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
state:
  enabled: true
  sweep_interval: -1s
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("got nil, want validation error for negative state.sweep_interval")
	}
	if !errors.Is(err, ErrInvalidSweepInterval) {
		t.Errorf("got %v, want ErrInvalidSweepInterval", err)
	}
}

func TestStateDisabledSkipsValidation(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
state:
  enabled: false
  ttl: -1s
`
	// state.enabled=false must skip validation entirely.
	if _, err := LoadReader(strings.NewReader(yaml)); err != nil {
		t.Fatalf("unexpected error when state disabled: %v", err)
	}
}

func TestStorageDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
storage:
  enabled: true
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Storage.Path != DefaultStoragePath {
		t.Errorf("got storage.path %q, want %q", cfg.Storage.Path, DefaultStoragePath)
	}
	if cfg.Storage.SnapshotInterval != DefaultSnapshotInterval {
		t.Errorf("got storage.snapshot_interval %v, want %v", cfg.Storage.SnapshotInterval, DefaultSnapshotInterval)
	}
	if cfg.Storage.MaxSnapshots != DefaultMaxSnapshots {
		t.Errorf("got storage.max_snapshots %d, want %d", cfg.Storage.MaxSnapshots, DefaultMaxSnapshots)
	}
	if cfg.Storage.MaxEvents != DefaultMaxEvents {
		t.Errorf("got storage.max_events %d, want %d", cfg.Storage.MaxEvents, DefaultMaxEvents)
	}
}

func TestStorageNegativeSnapshotIntervalValidation(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
storage:
  enabled: true
  snapshot_interval: -1s
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("got nil, want validation error for negative storage.snapshot_interval")
	}
	if !errors.Is(err, ErrInvalidSnapshotInterval) {
		t.Errorf("got %v, want ErrInvalidSnapshotInterval", err)
	}
}

func TestStorageDisabledSkipsValidation(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
storage:
  enabled: false
  snapshot_interval: -1s
`
	if _, err := LoadReader(strings.NewReader(yaml)); err != nil {
		t.Fatalf("unexpected error when storage disabled: %v", err)
	}
}

func TestAutoLearningDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
whitelist:
  auto_learning:
    enabled: true
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Whitelist.AutoLearning.Duration != DefaultAutoLearningDuration {
		t.Errorf("got auto_learning.duration %v, want %v",
			cfg.Whitelist.AutoLearning.Duration, DefaultAutoLearningDuration)
	}
}

func TestAutoLearningNegativeDurationValidation(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
whitelist:
  auto_learning:
    enabled: true
    duration: -1s
`
	_, err := LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("got nil, want validation error for negative auto_learning.duration")
	}
	if !errors.Is(err, ErrInvalidLearningDuration) {
		t.Errorf("got %v, want ErrInvalidLearningDuration", err)
	}
}

// --- API config tests ---

func TestAPIDefaults(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
api:
  enabled: false
`
	cfg, err := LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.API.Listen != DefaultAPIListen {
		t.Errorf("got listen %q, want %q", cfg.API.Listen, DefaultAPIListen)
	}
	if cfg.API.ReadTimeout != DefaultAPIReadTimeout {
		t.Errorf("got read_timeout %v, want %v", cfg.API.ReadTimeout, DefaultAPIReadTimeout)
	}
	if cfg.API.Auth.SessionTTL != DefaultAPISessionTTL {
		t.Errorf("got session_ttl %v, want %v", cfg.API.Auth.SessionTTL, DefaultAPISessionTTL)
	}
}

func TestAPIInvalidListen(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
api:
  enabled: true
  listen: "not-a-host-port"
  auth:
    enabled: false
`
	_, err := LoadReader(strings.NewReader(yaml))
	if !errors.Is(err, ErrInvalidAPIListen) {
		t.Errorf("got %v, want ErrInvalidAPIListen", err)
	}
}

func TestAPIAuthRequiresAdminHash(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
api:
  enabled: true
  listen: "127.0.0.1:8080"
  auth:
    enabled: true
`
	_, err := LoadReader(strings.NewReader(yaml))
	if !errors.Is(err, ErrMissingAdminHash) {
		t.Errorf("got %v, want ErrMissingAdminHash", err)
	}
}

func TestAPIRejectsBadBcryptHash(t *testing.T) {
	yaml := `
monitor:
  interface: wlan0
api:
  enabled: true
  listen: "127.0.0.1:8080"
  auth:
    enabled: true
    admin_password_hash: "plaintext-not-bcrypt"
`
	_, err := LoadReader(strings.NewReader(yaml))
	if !errors.Is(err, ErrInvalidPasswordHash) {
		t.Errorf("got %v, want ErrInvalidPasswordHash", err)
	}
}

func TestAPIAcceptsRealBcryptHash(t *testing.T) {
	// Standard bcrypt hash is exactly 60 characters: $2a$10$ + 53-char salt+hash.
	yaml := "\nmonitor:\n  interface: wlan0\napi:\n  enabled: true\n  listen: \"127.0.0.1:8080\"\n  auth:\n    enabled: true\n    admin_password_hash: \"$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0\"\n"
	if _, err := LoadReader(strings.NewReader(yaml)); err != nil {
		t.Errorf("got %v, want no error", err)
	}
}

func TestDefaultChannels2GHz(t *testing.T) {
	ch := DefaultChannels2GHz()
	if len(ch) != 13 {
		t.Errorf("expected 13 channels, got %d", len(ch))
	}
	if ch[0] != 1 || ch[12] != 13 {
		t.Errorf("expected channels 1..13, got %v..%v", ch[0], ch[12])
	}
}

func TestDefaultChannels5GHz(t *testing.T) {
	ch := DefaultChannels5GHz()
	if len(ch) != 9 {
		t.Errorf("expected 9 channels, got %d", len(ch))
	}
	if ch[0] != 36 {
		t.Errorf("expected first channel 36, got %d", ch[0])
	}
}

// TestStorageValidation_NegativeMaxSnapshots verifies negative max_snapshots is rejected.
func TestStorageValidation_NegativeMaxSnapshots(t *testing.T) {
	// Bypass defaults by constructing Config directly.
	cfg := &Config{
		Monitor: MonitorConfig{Interface: "wlan0",
			Capture:       CaptureConfig{Snaplen: DefaultSnaplen, BufferSize: DefaultBufferSize, Timeout: time.Second},
			ChannelHopping: ChannelHoppingConfig{Dwell: DefaultDwellTime},
		},
		Storage: StorageConfig{Enabled: true, Path: "/tmp/test.db", MaxSnapshots: -1, MaxEvents: 100},
	}
	err := validate(cfg)
	if !errors.Is(err, ErrInvalidMaxSnapshots) {
		t.Errorf("got %v, want ErrInvalidMaxSnapshots", err)
	}
}

// TestStorageValidation_NegativeMaxEvents verifies negative max_events is rejected.
func TestStorageValidation_NegativeMaxEvents(t *testing.T) {
	cfg := &Config{
		Monitor: MonitorConfig{Interface: "wlan0",
			Capture:       CaptureConfig{Snaplen: DefaultSnaplen, BufferSize: DefaultBufferSize, Timeout: time.Second},
			ChannelHopping: ChannelHoppingConfig{Dwell: DefaultDwellTime},
		},
		Storage: StorageConfig{Enabled: true, Path: "/tmp/test.db", MaxSnapshots: 5, MaxEvents: -1},
	}
	err := validate(cfg)
	if !errors.Is(err, ErrInvalidMaxEvents) {
		t.Errorf("got %v, want ErrInvalidMaxEvents", err)
	}
}

// TestAPIValidation_InvalidTimeout verifies zero/negative API timeouts are rejected.
func TestAPIValidation_InvalidTimeout(t *testing.T) {
	cfg := &Config{
		Monitor: MonitorConfig{Interface: "wlan0",
			Capture:       CaptureConfig{Snaplen: DefaultSnaplen, BufferSize: DefaultBufferSize, Timeout: time.Second},
			ChannelHopping: ChannelHoppingConfig{Dwell: DefaultDwellTime},
		},
		API: APIConfig{Enabled: true, Listen: "127.0.0.1:8080",
			ReadTimeout: 0, WriteTimeout: 0, IdleTimeout: 0, ShutdownTimeout: 0},
	}
	err := validate(cfg)
	if !errors.Is(err, ErrInvalidAPITimeout) {
		t.Errorf("got %v, want ErrInvalidAPITimeout", err)
	}
}

// TestAPIAuth_InvalidUserHash verifies bad user password hash is rejected.
func TestAPIAuth_InvalidUserHash(t *testing.T) {
	cfg := &Config{
		Monitor: MonitorConfig{Interface: "wlan0",
			Capture:       CaptureConfig{Snaplen: DefaultSnaplen, BufferSize: DefaultBufferSize, Timeout: time.Second},
			ChannelHopping: ChannelHoppingConfig{Dwell: DefaultDwellTime},
		},
		API: APIConfig{Enabled: true, Listen: "127.0.0.1:8080",
			ReadTimeout: time.Second, WriteTimeout: time.Second,
			IdleTimeout: time.Second, ShutdownTimeout: time.Second,
			Auth: AuthConfig{
				Enabled:           true,
				AdminPasswordHash: "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0",
				UserPasswordHash:  "not-a-bcrypt-hash",
			},
		},
	}
	err := validate(cfg)
	if !errors.Is(err, ErrInvalidPasswordHash) {
		t.Errorf("got %v, want ErrInvalidPasswordHash", err)
	}
}

// TestLooksLikeBcrypt verifies bcrypt hash syntax detection.
func TestLooksLikeBcrypt(t *testing.T) {
	// Wrong length.
	if looksLikeBcrypt("short") {
		t.Error("short string should not look like bcrypt")
	}
	if looksLikeBcrypt("$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ00") {
		t.Error("61-char string should not look like bcrypt")
	}
	// Wrong prefix.
	if looksLikeBcrypt("$2x$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0") {
		t.Error("$2x$ prefix should not look like bcrypt")
	}
	// Valid prefixes.
	if !looksLikeBcrypt("$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0") {
		t.Error("$2a$ prefix should look like bcrypt")
	}
	if !looksLikeBcrypt("$2b$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0") {
		t.Error("$2b$ prefix should look like bcrypt")
	}
	if !looksLikeBcrypt("$2y$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0") {
		t.Error("$2y$ prefix should look like bcrypt")
	}
}

func TestDefaultPrimaryChannels(t *testing.T) {
	ch := DefaultPrimaryChannels()
	if len(ch) != 3 {
		t.Errorf("expected 3 channels, got %d", len(ch))
	}
	expected := []int{1, 6, 11}
	for i, v := range expected {
		if ch[i] != v {
			t.Errorf("channel[%d] = %d, want %d", i, ch[i], v)
		}
	}
}
