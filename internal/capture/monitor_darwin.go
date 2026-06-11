//go:build darwin

package capture

/*
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation
#include <stdbool.h>
#include <stdlib.h>

// SetInterfaceChannel returns NULL on success, or a heap-allocated error
// string (owned by caller, free with C.free) on failure.
char* SetInterfaceChannel(const char *iface, int channel);

// GetSupportedWLANChannels returns a space-separated list of supported
// channel numbers (e.g. "1 6 11 36 40"), or NULL on failure. On failure,
// *errStr is set to a heap-allocated error string. Both return values
// must be freed with C.free.
char* GetSupportedWLANChannels(const char *iface, char **errStr);
*/
import "C" //nolint:gocritic // cgo pseudo-package; gocritic false positive with "unsafe"

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"unsafe" //nolint:gocritic // gocritic false positive with cgo's "C" pseudo-package
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

// SupportedChannels returns the list of WiFi channels the interface supports.
// Queries CoreWLAN's supportedWLANChannels property for the given interface.
// Returns (nil, nil) on failure — callers should fall back to trial-and-error.
func (m *darwinMonitor) SupportedChannels(ctx context.Context, iface string) ([]int, error) {
	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(cIface))

	var cErr *C.char
	cChannels := C.GetSupportedWLANChannels(cIface, &cErr) //nolint:gocritic // cgo dupSubExpr false positive
	if cErr != nil {
		errMsg := C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
		slog.Warn("failed to query supported channels, falling back to trial-and-error",
			"interface", iface,
			"error", errMsg,
		)
		return nil, nil
	}
	defer C.free(unsafe.Pointer(cChannels))

	channelsStr := strings.TrimSpace(C.GoString(cChannels))
	if channelsStr == "" {
		return nil, nil
	}

	var channels []int
	for field := range strings.FieldsSeq(channelsStr) {
		ch, err := strconv.Atoi(field)
		if err != nil {
			slog.Warn("unexpected channel number in supported list, skipping",
				"value", field,
				"error", err,
			)
			continue
		}
		channels = append(channels, ch)
	}
	return channels, nil
}

// SetChannel sets the WiFi interface to the specified channel via CoreWLAN.
// Channel switching on macOS has 1-3 second overhead, which is accounted for
// by the channel hopper's dwell time enforcement (min 1s, recommended 2s+).
func (m *darwinMonitor) SetChannel(ctx context.Context, iface string, channel int) error {
	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(cIface))

	cErr := C.SetInterfaceChannel(cIface, C.int(channel))
	if cErr != nil {
		errMsg := C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
		return fmt.Errorf("CoreWLAN channel %d on %s: %s", channel, iface, errMsg)
	}
	return nil
}
