//go:build linux

package capture

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

// linuxMonitor implements MonitorModeManager using the iw and ip system utilities.
type linuxMonitor struct{}

// NewMonitorModeManager creates a MonitorModeManager backed by iw/ip commands.
func NewMonitorModeManager() (MonitorModeManager, error) {
	if _, err := exec.LookPath("iw"); err != nil {
		return nil, fmt.Errorf("iw utility not found: %w", err)
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return nil, fmt.Errorf("ip utility not found: %w", err)
	}
	return &linuxMonitor{}, nil
}

// IsSupported returns true indicating that monitor mode is available on Linux.
func (m *linuxMonitor) IsSupported() bool {
	return true
}

// EnableMonitor switches the interface to monitor mode and brings it up.
func (m *linuxMonitor) EnableMonitor(ctx context.Context, iface string) error {
	// Set interface type to monitor.
	if err := runCmd(ctx, "iw", "dev", iface, "set", "type", "monitor"); err != nil {
		return fmt.Errorf("failed to set monitor mode on %s: %w", iface, err)
	}
	// Bring the interface up.
	if err := runCmd(ctx, "ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("failed to bring up %s: %w", iface, err)
	}
	return nil
}

// DisableMonitor returns the interface to managed mode and brings it up.
func (m *linuxMonitor) DisableMonitor(ctx context.Context, iface string) error {
	if err := runCmd(ctx, "iw", "dev", iface, "set", "type", "managed"); err != nil {
		return fmt.Errorf("failed to set managed mode on %s: %w", iface, err)
	}
	if err := runCmd(ctx, "ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("failed to bring up %s: %w", iface, err)
	}
	return nil
}

// SetChannel sets the interface to the specified WiFi channel.
func (m *linuxMonitor) SetChannel(ctx context.Context, iface string, channel int) error {
	return runCmd(ctx, "iw", "dev", iface, "set", "channel", strconv.Itoa(channel))
}

// runCmd executes a command and returns an error if it fails, including stderr.
func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // name is always a hardcoded string from callers within this file
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, string(output))
	}
	return nil
}
