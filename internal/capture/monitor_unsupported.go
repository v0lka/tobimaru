//go:build !linux && !darwin

package capture

// NewMonitorModeManager returns a stub MonitorModeManager for unsupported platforms.
// On non-Linux, non-macOS platforms, monitor mode is not available.
func NewMonitorModeManager() (MonitorModeManager, error) {
	return &unsupportedMonitor{}, nil
}

type unsupportedMonitor struct{}

func (m *unsupportedMonitor) EnableMonitor(iface string) error           { return ErrNotSupported }
func (m *unsupportedMonitor) DisableMonitor(iface string) error          { return ErrNotSupported }
func (m *unsupportedMonitor) SetChannel(iface string, channel int) error { return ErrNotSupported }
func (m *unsupportedMonitor) IsSupported() bool                          { return false }
