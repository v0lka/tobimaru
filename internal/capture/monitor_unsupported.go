//go:build !linux && !darwin

package capture

import "context"

// NewMonitorModeManager returns a stub MonitorModeManager for unsupported platforms.
// On non-Linux, non-macOS platforms, monitor mode is not available.
func NewMonitorModeManager() (MonitorModeManager, error) {
	return &unsupportedMonitor{}, nil
}

type unsupportedMonitor struct{}

func (m *unsupportedMonitor) EnableMonitor(_ context.Context, _ string) error { return ErrNotSupported }
func (m *unsupportedMonitor) DisableMonitor(_ context.Context, _ string) error {
	return ErrNotSupported
}
func (m *unsupportedMonitor) SetChannel(_ context.Context, _ string, _ int) error {
	return ErrNotSupported
}
func (m *unsupportedMonitor) SupportedChannels(_ context.Context, _ string) ([]int, error) {
	return nil, ErrNotSupported
}
func (m *unsupportedMonitor) IsSupported() bool { return false }
