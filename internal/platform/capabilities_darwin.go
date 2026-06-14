//go:build darwin

package platform

// Detect returns the capabilities for the macOS (darwin) platform.
// Monitor mode is always available via BPF pcap. Channel hopping is
// available via CoreWLAN cgo bridge. Frame injection is never supported
// on built-in adapters.
func Detect() Capabilities {
	return Capabilities{
		MonitorMode:    true,
		FrameInjection: false, // macOS never supports 802.11 frame injection on built-in adapters
		ChannelHopping: true,
		MaxChannels:    1, // can only listen on one channel at a time
		SlowHopping:    true,
		SingleAdapter:  true,
	}
}
