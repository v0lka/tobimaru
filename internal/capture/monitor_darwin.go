//go:build darwin

package capture

/*
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation
#include <stdbool.h>
#include <stdlib.h>

bool SetInterfaceChannel(const char *iface, int channel);
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"unsafe"
)

// darwinMonitor implements MonitorModeManager using CoreWLAN for channel
// switching and relying on BPF SetRFMon (pcap) for monitor mode activation.
//
// On macOS, the actual monitor mode switch is performed by pcap.SetRFMon(true)
// in OpenCapture(), which issues the BIOCSRFMON ioctl. EnableMonitor logs an
// informational message but does not need to issue any OS-level commands —
// the BPF ioctl handles disassociation automatically.
//
// Channel switching uses CoreWLAN via cgo (see monitor_darwin.m). The channel
// hopper's Run() method handles SetChannel errors gracefully with backoff.
type darwinMonitor struct{}

// NewMonitorModeManager creates a MonitorModeManager for macOS.
// Monitor mode is always available on macOS via BPF (pcap).
func NewMonitorModeManager() (MonitorModeManager, error) {
	return &darwinMonitor{}, nil
}

// IsSupported reports whether monitor mode is available on this platform.
// Always true on macOS — BPF RFMon works on all versions.
func (m *darwinMonitor) IsSupported() bool {
	return true
}

// EnableMonitor prepares the interface for monitor mode capture.
// The actual monitor mode activation is performed by pcap.SetRFMon(true)
// in OpenCapture(). The BPF ioctl handles disassociation from the current
// network automatically. The user must ensure they are not connected to WiFi
// on the same adapter before starting capture.
func (m *darwinMonitor) EnableMonitor(ctx context.Context, iface string) error {
	slog.Info("enabling monitor mode via BPF SetRFMon; ensure WiFi is disconnected manually before capture",
		"interface", iface)
	return nil
}

// DisableMonitor restores the interface state. Since the macOS wireless stack
// typically reconnects automatically after pcap closes the BPF handle, this
// is a no-op.
func (m *darwinMonitor) DisableMonitor(ctx context.Context, iface string) error {
	return nil
}

// SetChannel sets the WiFi interface to the specified channel via CoreWLAN.
// Channel switching on macOS has 1-3 second overhead, which is accounted for
// by the channel hopper's dwell time enforcement (min 1s, recommended 2s+).
func (m *darwinMonitor) SetChannel(ctx context.Context, iface string, channel int) error {
	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(cIface))

	success := C.SetInterfaceChannel(cIface, C.int(channel))
	if !success {
		return fmt.Errorf("failed to set channel %d on %s via CoreWLAN", channel, iface)
	}
	return nil
}
