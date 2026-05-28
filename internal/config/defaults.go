package config

// DefaultChannels2GHz returns the list of 2.4 GHz WiFi channels (1-13, ETSI domain).
func DefaultChannels2GHz() []int {
	channels := make([]int, 13)
	for i := range channels {
		channels[i] = i + 1
	}
	return channels
}

// DefaultChannels5GHz returns the list of 5 GHz WiFi channels (non-DFS + DFS, FCC domain).
func DefaultChannels5GHz() []int {
	return []int{
		36, 40, 44, 48, // UNII-1
		52, 56, 60, 64, // UNII-2 (DFS)
		100, 104, 108, 112, 116, // UNII-2e (DFS)
		120, 124, 128, 132, 136, 140, 144, // UNII-2e/UNII-3 (DFS)
		149, 153, 157, 161, 165, // UNII-3
	}
}

func applyDefaults(cfg *Config) {
	if cfg.Log.Level == "" {
		cfg.Log.Level = DefaultLogLevel
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = DefaultLogFormat
	}
	if cfg.Monitor.Capture.Snaplen == 0 {
		cfg.Monitor.Capture.Snaplen = DefaultSnaplen
	}
	if cfg.Monitor.Capture.BufferSize == 0 {
		cfg.Monitor.Capture.BufferSize = DefaultBufferSize
	}
	if cfg.Monitor.Capture.Timeout == 0 {
		cfg.Monitor.Capture.Timeout = DefaultTimeout
	}
	if cfg.Monitor.ChannelHopping.Dwell == 0 {
		cfg.Monitor.ChannelHopping.Dwell = DefaultDwellTime
	}
	if cfg.Monitor.ChannelHopping.Channels2GHz == nil {
		cfg.Monitor.ChannelHopping.Channels2GHz = DefaultChannels2GHz()
	}
	if cfg.Monitor.ChannelHopping.Channels5GHz == nil {
		cfg.Monitor.ChannelHopping.Channels5GHz = DefaultChannels5GHz()
	}
	if cfg.Monitor.ChannelHopping.WeightedDwell.Multiplier == 0 {
		cfg.Monitor.ChannelHopping.WeightedDwell.Multiplier = DefaultMultiplier
	}
	if cfg.Monitor.Capture.Promiscuous == nil {
		v := DefaultPromiscuous
		cfg.Monitor.Capture.Promiscuous = &v
	}
	if cfg.Detection.DedupWindow == 0 {
		cfg.Detection.DedupWindow = DefaultDedupWindow
	}
	if cfg.Detection.AlertBufferSize == 0 {
		cfg.Detection.AlertBufferSize = DefaultAlertBufferSize
	}
}
