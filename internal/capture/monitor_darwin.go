//go:build darwin

package capture

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/vkochetkov/tobimaru/internal/platform"
)

const (
	// airportSymlink is the standard user-installed symlink to the airport utility.
	airportSymlink = "/usr/local/bin/airport"
	// airportFrameworkPath is the absolute path to the airport binary inside
	// the Apple80211 private framework.
	airportFrameworkPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
)

// darwinMonitor implements MonitorModeManager using the macOS airport utility.
// The airport utility is an undocumented tool from Apple that allows switching
// the WiFi interface into monitor mode for packet capture.
type darwinMonitor struct {
	airportPath string // resolved path to the airport binary
}

// NewMonitorModeManager creates a MonitorModeManager backed by the airport utility.
// It validates that the airport utility is available on the system.
func NewMonitorModeManager() (MonitorModeManager, error) {
	if !platform.AirportAvailable() {
		return nil, fmt.Errorf("airport utility not found at %s or %s: install it with: sudo ln -s \"%s\" /usr/local/bin/airport",
			airportSymlink, airportFrameworkPath, airportFrameworkPath)
	}
	// Resolve the airport path for command execution.
	path, err := exec.LookPath("airport")
	if err != nil {
		path = airportFrameworkPath
	}
	return &darwinMonitor{airportPath: path}, nil
}

func (m *darwinMonitor) IsSupported() bool {
	return true
}

// EnableMonitor disconnects from any WiFi network on the given interface.
// This is required before activating RFMon mode on the BPF device.
// On macOS, the actual monitor mode is activated by SetRFMon(true) in OpenCapture().
func (m *darwinMonitor) EnableMonitor(ctx context.Context, iface string) error {
	return m.runAirport(ctx, iface, "-z")
}

// DisableMonitor resets the airport state. The macOS wireless stack typically
// reconnects automatically after a brief delay.
func (m *darwinMonitor) DisableMonitor(ctx context.Context, iface string) error {
	return m.runAirport(ctx, iface, "-z")
}

// SetChannel sets the interface to the specified WiFi channel.
// Note: this operation can take 1-3 seconds on macOS, which makes channel
// hopping significantly slower than on Linux.
func (m *darwinMonitor) SetChannel(ctx context.Context, iface string, channel int) error {
	return m.runAirport(ctx, iface, "--channel="+strconv.Itoa(channel))
}

// runAirport executes the airport utility with interface and arguments.
func (m *darwinMonitor) runAirport(ctx context.Context, iface string, args ...string) error {
	return runDarwinCmd(ctx, m.airportPath, append([]string{iface}, args...)...)
}

// runDarwinCmd executes a command and returns an error if it fails, including stderr.
func runDarwinCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, string(output))
	}
	return nil
}
