// Package capture provides WiFi capture infrastructure: monitor mode management,
// packet capture via pcap, channel hopping, and the frame pipeline.
package capture

import (
	"context"
	"errors"
)

// ErrNotSupported is returned when a platform does not support monitor mode.
var ErrNotSupported = errors.New("monitor mode is not supported on this platform")

// MonitorModeManager manages the WiFi interface's operation mode and channel.
// Platform-specific implementations handle the OS-level commands to switch between
// managed and monitor modes and to set the operating channel.
type MonitorModeManager interface {
	// EnableMonitor switches the given interface to monitor mode.
	EnableMonitor(ctx context.Context, iface string) error

	// DisableMonitor returns the given interface to managed mode.
	DisableMonitor(ctx context.Context, iface string) error

	// SetChannel sets the interface's operating channel.
	SetChannel(ctx context.Context, iface string, channel int) error

	// SupportedChannels returns the list of channel numbers the interface
	// supports for the given interface. Returns (nil, nil) when the platform
	// cannot enumerate channels — in that case all configured channels are
	// assumed to be supported (the caller falls back to trial-and-error).
	SupportedChannels(ctx context.Context, iface string) ([]int, error)

	// IsSupported reports whether monitor mode is available on this platform.
	IsSupported() bool
}
