// Package config provides YAML configuration loading, validation, and defaults.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Sentinel errors for configuration validation.
var (
	ErrMissingInterface  = errors.New("monitor.interface is required")
	ErrInvalidLogLevel   = errors.New("log.level must be one of: debug, info, warn, error")
	ErrInvalidLogFormat  = errors.New("log.format must be one of: text, json")
	ErrInvalidSnaplen    = errors.New("monitor.capture.snaplen must be positive")
	ErrInvalidBufferSize = errors.New("monitor.capture.buffer_size must be positive")
	ErrInvalidTimeout    = errors.New("monitor.capture.timeout must be positive")
)

// Config holds the complete application configuration.
type Config struct {
	Log       LogConfig       `yaml:"log"`
	Monitor   MonitorConfig   `yaml:"monitor"`
	Detection DetectionConfig `yaml:"detection"`
	State     StateConfig     `yaml:"state"`
	Whitelist WhitelistConfig `yaml:"whitelist"`
	Storage   StorageConfig   `yaml:"storage"`
}

// DetectionConfig holds intrusion detection configuration.
type DetectionConfig struct {
	// Enabled is the master switch for the detection engine.
	Enabled bool `yaml:"enabled"`

	// DedupWindow is the time window for suppressing duplicate alerts
	// with the same event type and MAC participants.
	DedupWindow time.Duration `yaml:"dedup_window"`

	// AlertBufferSize is the capacity of the buffered alerts channel.
	AlertBufferSize int `yaml:"alert_buffer_size"`
}

// StateConfig holds network state engine configuration.
type StateConfig struct {
	// Enabled is the master switch for the state engine.
	Enabled bool `yaml:"enabled"`

	// TTL is the duration after which unobserved APs/clients are evicted.
	TTL time.Duration `yaml:"ttl"`

	// SweepInterval is how often the eviction sweep runs.
	SweepInterval time.Duration `yaml:"sweep_interval"`
}

// WhitelistConfig holds whitelist/blacklist and auto-learning configuration.
type WhitelistConfig struct {
	AutoLearning AutoLearningConfig `yaml:"auto_learning"`
}

// AutoLearningConfig holds auto-learning mode settings.
type AutoLearningConfig struct {
	// Enabled activates auto-learning mode at startup.
	Enabled bool `yaml:"enabled"`

	// Duration is the length of the learning phase.
	Duration time.Duration `yaml:"duration"`
}

// StorageConfig holds persistent storage configuration.
type StorageConfig struct {
	// Enabled is the master switch for SQLite storage.
	Enabled bool `yaml:"enabled"`

	// Path is the SQLite database file path.
	Path string `yaml:"path"`

	// SnapshotInterval is how often state snapshots are persisted.
	SnapshotInterval time.Duration `yaml:"snapshot_interval"`

	// MaxSnapshots is the maximum number of snapshots to retain.
	MaxSnapshots int `yaml:"max_snapshots"`

	// MaxEvents is the maximum number of security events to retain.
	MaxEvents int `yaml:"max_events"`
}

// Log level string constants used in configuration.
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// Log format string constants used in configuration.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// Default values for configuration fields.
const (
	DefaultLogLevel        = LogLevelInfo
	DefaultLogFormat       = LogFormatText
	DefaultSnaplen         = 65535
	DefaultBufferSize      = 2097152 // 2 MB
	DefaultTimeout         = 100 * time.Millisecond
	DefaultDwellTime       = 300 * time.Millisecond
	DefaultWeightedDwell   = true
	DefaultPromiscuous     = true
	DefaultMultiplier      = 2.5
	DefaultDedupWindow     = 30 * time.Second
	DefaultAlertBufferSize = 256
	DefaultFrameBufferSize = 1024

	// State engine defaults.
	DefaultStateTTL           = 10 * time.Minute
	DefaultStateSweepInterval = 1 * time.Minute

	// Auto-learning defaults.
	DefaultAutoLearningDuration = 15 * time.Minute

	// Storage defaults.
	DefaultStoragePath      = "tobimaru.db"
	DefaultSnapshotInterval = 5 * time.Minute
	DefaultMaxSnapshots     = 288 // 24 hours at 5-minute intervals
	DefaultMaxEvents        = 100000
)

// LogConfig holds logging-related configuration.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text, json
}

// MonitorConfig holds WiFi monitor configuration.
type MonitorConfig struct {
	Interface      string               `yaml:"interface"`       // WiFi interface name (e.g., wlan0)
	Capture        CaptureConfig        `yaml:"capture"`         // pcap capture settings
	ChannelHopping ChannelHoppingConfig `yaml:"channel_hopping"` // channel hopping settings
}

// CaptureConfig holds pcap capture settings.
type CaptureConfig struct {
	Snaplen         int           `yaml:"snaplen"`           // max bytes per packet
	BufferSize      int           `yaml:"buffer_size"`       // pcap buffer size in bytes
	FrameBufferSize int           `yaml:"frame_buffer_size"` // parsed frame channel buffer size
	Promiscuous     *bool         `yaml:"promiscuous"`       // promiscuous mode; defaults to true
	Timeout         time.Duration `yaml:"timeout"`           // pcap read timeout
}

// ChannelHoppingConfig holds channel hopping settings.
type ChannelHoppingConfig struct {
	Enabled       bool                `yaml:"enabled"`        // enable channel hopping
	Dwell         time.Duration       `yaml:"dwell"`          // base dwell time per channel
	WeightedDwell WeightedDwellConfig `yaml:"weighted_dwell"` // weighted dwell config
	Channels2GHz  []int               `yaml:"channels_2ghz"`  // 2.4 GHz channels
	Channels5GHz  []int               `yaml:"channels_5ghz"`  // 5 GHz channels
	Include5GHz   bool                `yaml:"include_5ghz"`   // include 5 GHz channels
}

// WeightedDwellConfig holds weighted dwell time settings for primary channels.
type WeightedDwellConfig struct {
	Enabled         bool    `yaml:"enabled"`          // enable weighted dwell
	PrimaryChannels []int   `yaml:"primary_channels"` // channels to spend more time on
	Multiplier      float64 `yaml:"multiplier"`       // time multiplier for primary channels
}

// ValidationError wraps multiple field-level validation errors.
type ValidationError struct {
	Errors []error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("configuration validation failed: %v", errors.Join(e.Errors...))
}

// Unwrap returns the list of underlying validation errors so that callers
// can use errors.Is / errors.As against individual sentinel errors.
func (e *ValidationError) Unwrap() []error {
	return e.Errors
}

// Load reads a YAML configuration file from the given path, applies defaults,
// and validates required fields.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %q: %w", path, err)
	}
	defer f.Close()
	return LoadReader(f)
}

// LoadReader reads YAML configuration from an io.Reader, applies defaults,
// and validates required fields.
func LoadReader(r io.Reader) (*Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
