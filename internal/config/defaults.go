package config

// DefaultChannels2GHz returns the list of 2.4 GHz WiFi channels (1-13, ETSI domain).
func DefaultChannels2GHz() []int {
	channels := make([]int, 13)
	for i := range channels {
		channels[i] = i + 1
	}
	return channels
}

// DefaultChannels5GHz returns the list of 5 GHz WiFi channels commonly
// supported on macOS adapters (non-DFS, UNII-1 + UNII-3). Used as a
// fallback when the platform cannot enumerate hardware-supported channels
// (e.g., Linux where SupportedChannels returns nil).
func DefaultChannels5GHz() []int {
	return []int{
		36, 40, 44, 48, // UNII-1
		149, 153, 157, 161, 165, // UNII-3
	}
}

// DefaultPrimaryChannels returns the non-overlapping 2.4 GHz channels used as
// primary channels for weighted dwell time.
func DefaultPrimaryChannels() []int {
	return []int{1, 6, 11}
}

func applyDefaults(cfg *Config) { //nolint:gocyclo // sequential zero-value checks, not branching complexity
	// Log defaults.
	if cfg.Log.Level == "" {
		cfg.Log.Level = DefaultLogLevel
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = DefaultLogFormat
	}

	// Capture defaults.
	if cfg.Monitor.Capture.Snaplen == 0 {
		cfg.Monitor.Capture.Snaplen = DefaultSnaplen
	}
	if cfg.Monitor.Capture.BufferSize == 0 {
		cfg.Monitor.Capture.BufferSize = DefaultBufferSize
	}
	if cfg.Monitor.Capture.FrameBufferSize == 0 {
		cfg.Monitor.Capture.FrameBufferSize = DefaultFrameBufferSize
	}
	if cfg.Monitor.Capture.Timeout == 0 {
		cfg.Monitor.Capture.Timeout = DefaultTimeout
	}
	if cfg.Monitor.Capture.Promiscuous == nil {
		v := DefaultPromiscuous
		cfg.Monitor.Capture.Promiscuous = &v
	}

	// Channel hopping defaults (only dwell and multiplier — channel lists
	// are auto-populated at pipeline creation from hardware-supported channels
	// or code defaults; see internal/capture/pipeline.go).
	if cfg.Monitor.ChannelHopping.Dwell == 0 {
		cfg.Monitor.ChannelHopping.Dwell = DefaultDwellTime
	}
	if cfg.Monitor.ChannelHopping.WeightedDwell.Multiplier == 0 {
		cfg.Monitor.ChannelHopping.WeightedDwell.Multiplier = DefaultMultiplier
	}
	if cfg.Monitor.ChannelHopping.WeightedDwell.Enabled == nil {
		v := DefaultWeightedDwell
		cfg.Monitor.ChannelHopping.WeightedDwell.Enabled = &v
	}

	// Detection defaults.
	if cfg.Detection.DedupWindow == 0 {
		cfg.Detection.DedupWindow = DefaultDedupWindow
	}
	if cfg.Detection.AlertBufferSize == 0 {
		cfg.Detection.AlertBufferSize = DefaultAlertBufferSize
	}

	// Detection rule defaults.
	if cfg.Detection.DeauthFlood.Threshold == 0 {
		cfg.Detection.DeauthFlood.Threshold = DefaultDeauthFloodThreshold
	}
	if cfg.Detection.DeauthFlood.Window == 0 {
		cfg.Detection.DeauthFlood.Window = DefaultDeauthFloodWindow
	}
	if cfg.Detection.DisassocFlood.Threshold == 0 {
		cfg.Detection.DisassocFlood.Threshold = DefaultDisassocFloodThreshold
	}
	if cfg.Detection.DisassocFlood.Window == 0 {
		cfg.Detection.DisassocFlood.Window = DefaultDisassocFloodWindow
	}
	if cfg.Detection.BeaconFlood.Threshold == 0 {
		cfg.Detection.BeaconFlood.Threshold = DefaultBeaconFloodThreshold
	}
	if cfg.Detection.BeaconFlood.Window == 0 {
		cfg.Detection.BeaconFlood.Window = DefaultBeaconFloodWindow
	}
	if cfg.Detection.BeaconFlood.LearningPeriod == 0 {
		cfg.Detection.BeaconFlood.LearningPeriod = DefaultBeaconFloodLearningPeriod
	}
	if cfg.Detection.EvilTwin.ScoreThreshold == 0 {
		cfg.Detection.EvilTwin.ScoreThreshold = DefaultEvilTwinScoreThreshold
	}
	if cfg.Detection.EvilTwin.StaleTimeout == 0 {
		cfg.Detection.EvilTwin.StaleTimeout = DefaultEvilTwinStaleTimeout
	}
	if cfg.Detection.EvilTwin.LearningPeriod == 0 {
		cfg.Detection.EvilTwin.LearningPeriod = DefaultEvilTwinLearningPeriod
	}
	if cfg.Detection.EvilTwin.MinBeacons == 0 {
		cfg.Detection.EvilTwin.MinBeacons = DefaultEvilTwinMinBeacons
	}
	if cfg.Detection.UnauthorizedDevice.Cooldown == 0 {
		cfg.Detection.UnauthorizedDevice.Cooldown = DefaultUnauthorizedDeviceCooldown
	}

	// State engine defaults.
	if cfg.State.TTL == 0 {
		cfg.State.TTL = DefaultStateTTL
	}
	if cfg.State.SweepInterval == 0 {
		cfg.State.SweepInterval = DefaultStateSweepInterval
	}

	// Auto-learning defaults.
	if cfg.Whitelist.AutoLearning.Duration == 0 {
		cfg.Whitelist.AutoLearning.Duration = DefaultAutoLearningDuration
	}

	// Storage defaults.
	if cfg.Storage.Path == "" {
		cfg.Storage.Path = DefaultStoragePath
	}
	if cfg.Storage.SnapshotInterval == 0 {
		cfg.Storage.SnapshotInterval = DefaultSnapshotInterval
	}
	if cfg.Storage.MaxSnapshots == 0 {
		cfg.Storage.MaxSnapshots = DefaultMaxSnapshots
	}
	if cfg.Storage.MaxEvents == 0 {
		cfg.Storage.MaxEvents = DefaultMaxEvents
	}

	// API defaults.
	if cfg.API.Listen == "" {
		cfg.API.Listen = DefaultAPIListen
	}
	if cfg.API.ReadTimeout == 0 {
		cfg.API.ReadTimeout = DefaultAPIReadTimeout
	}
	if cfg.API.WriteTimeout == 0 {
		cfg.API.WriteTimeout = DefaultAPIWriteTimeout
	}
	if cfg.API.IdleTimeout == 0 {
		cfg.API.IdleTimeout = DefaultAPIIdleTimeout
	}
	if cfg.API.ShutdownTimeout == 0 {
		cfg.API.ShutdownTimeout = DefaultAPIShutdownTimeout
	}
	if cfg.API.Auth.SessionTTL == 0 {
		cfg.API.Auth.SessionTTL = DefaultAPISessionTTL
	}
	// CookieSecure defaults to true (secure-by-default for HTTPS deployments).
	// Operators serving the dashboard over plain HTTP on loopback for local
	// development can override this to false in YAML.
	if cfg.API.Auth.CookieSecure == nil {
		v := true
		cfg.API.Auth.CookieSecure = &v
	}
}
