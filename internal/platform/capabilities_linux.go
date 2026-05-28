//go:build linux

package platform

// Detect returns the capabilities for the Linux platform.
func Detect() Capabilities {
	return Capabilities{
		MonitorMode:    true,
		FrameInjection: true,
		ChannelHopping: true,
		MaxChannels:    0, // unlimited
		SlowHopping:    false,
		SingleAdapter:  false,
	}
}
