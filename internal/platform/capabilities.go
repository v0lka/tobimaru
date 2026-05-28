// Package platform provides runtime detection of OS-level capabilities and
// limitations relevant to WiFi monitoring. It is a self-contained leaf package
// with no dependencies on other internal packages.
package platform

// Capabilities describes what WiFi monitoring features the current platform supports.
type Capabilities struct {
	// MonitorMode indicates whether the platform supports monitor mode capture.
	MonitorMode bool

	// FrameInjection indicates whether the platform can inject 802.11 frames.
	FrameInjection bool

	// ChannelHopping indicates whether the platform can switch channels at runtime.
	ChannelHopping bool

	// MaxChannels is the maximum number of channels that can be monitored in one cycle.
	// 0 means unlimited, 1 means single-channel only.
	MaxChannels int

	// SlowHopping indicates that channel switching is significantly slower than dwell time.
	// When true, pipelines should increase dwell time to compensate for switching overhead.
	SlowHopping bool

	// SingleAdapter indicates that the system has only one WiFi adapter and cannot
	// simultaneously operate in monitor and managed mode.
	SingleAdapter bool
}

// ReportLimitations returns a human-readable list of platform limitations.
// Returns nil if no limitations exist.
func (c Capabilities) ReportLimitations() []string {
	var lims []string
	if !c.MonitorMode {
		lims = append(lims, "monitor mode is not available")
	}
	if !c.FrameInjection {
		lims = append(lims, "frame injection is not supported")
	}
	if c.MaxChannels == 1 {
		lims = append(lims, "single channel only; full channel hopping is not available")
	}
	if c.SlowHopping {
		lims = append(lims, "channel switching has high overhead; increase dwell time")
	}
	if c.SingleAdapter {
		lims = append(lims, "single WiFi adapter; cannot operate in monitor and managed mode simultaneously")
	}
	return lims
}
