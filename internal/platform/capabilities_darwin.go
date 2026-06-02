//go:build darwin

package platform

import "os/exec"

// airportSymlink is the standard user-installed symlink to the airport utility.
const airportSymlink = "/usr/local/bin/airport"

// airportFrameworkPath is the absolute path to the airport binary inside
// the Apple80211 private framework.
const airportFrameworkPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

// Detect returns the capabilities for the macOS (darwin) platform.
// It checks for the airport utility to determine if monitor mode is available.
func Detect() Capabilities {
	monitorAvailable := AirportAvailable()

	return Capabilities{
		MonitorMode:    monitorAvailable,
		FrameInjection: false, // macOS never supports 802.11 frame injection on built-in adapters
		ChannelHopping: monitorAvailable,
		MaxChannels:    1, // can only listen on one channel at a time
		SlowHopping:    true,
		SingleAdapter:  true,
	}
}

// AirportAvailable checks whether the airport utility is available.
// It tries the symlink location first, then the framework path.
func AirportAvailable() bool {
	_, err := exec.LookPath("airport")
	if err == nil {
		return true
	}
	_, err = exec.LookPath(airportSymlink)
	if err == nil {
		return true
	}
	_, err = exec.LookPath(airportFrameworkPath)
	return err == nil
}
