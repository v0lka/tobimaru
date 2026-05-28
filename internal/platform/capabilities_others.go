//go:build !linux && !darwin

package platform

// Detect returns the capabilities for unsupported platforms.
// All WiFi monitoring features are unavailable.
func Detect() Capabilities {
	return Capabilities{
		MonitorMode:    false,
		FrameInjection: false,
		ChannelHopping: false,
		MaxChannels:    0,
		SlowHopping:    false,
		SingleAdapter:  false,
	}
}
