// Package capture provides WiFi capture infrastructure: monitor mode management,
// packet capture via pcap, channel hopping, and the frame pipeline.
package capture

import "errors"

// ErrNotSupported is returned when a platform does not support monitor mode.
var ErrNotSupported = errors.New("monitor mode is not supported on this platform")

// MonitorModeManager manages the WiFi interface's operation mode and channel.
// Platform-specific implementations handle the OS-level commands to switch between
// managed and monitor modes and to set the operating channel.
type MonitorModeManager interface {
	// EnableMonitor switches the given interface to monitor mode.
	EnableMonitor(iface string) error

	// DisableMonitor returns the given interface to managed mode.
	DisableMonitor(iface string) error

	// SetChannel sets the interface's operating channel.
	SetChannel(iface string, channel int) error

	// IsSupported reports whether monitor mode is available on this platform.
	IsSupported() bool
}
