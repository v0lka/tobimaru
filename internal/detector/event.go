package detector

import (
	"fmt"
	"net"
	"time"
)

// Severity represents the severity level of a security event.
type Severity int

const (
	// SeverityInfo indicates an informational event with no immediate threat.
	SeverityInfo Severity = iota
	// SeverityWarning indicates a potential threat that requires attention.
	SeverityWarning
	// SeverityCritical indicates an active attack requiring immediate action.
	SeverityCritical
)

// String returns the human-readable name of the severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// SecurityEvent represents a detected security event or attack.
// It contains all fields required by the Phase 2 Definition of Done:
// timestamp, type, severity, MAC participants, channel, RSSI, and metadata.
type SecurityEvent struct {
	// Timestamp is the time when the event was detected.
	Timestamp time.Time

	// EventType identifies the type of attack (e.g., "deauth_flood", "evil_twin").
	EventType string

	// Severity indicates the severity level of the event.
	Severity Severity

	// SrcMAC is the MAC address of the attacking device (source).
	SrcMAC net.HardwareAddr

	// DstMAC is the MAC address of the victim device (destination).
	DstMAC net.HardwareAddr

	// BSSID is the BSSID of the targeted or spoofed access point.
	BSSID net.HardwareAddr

	// SSID is the network name associated with the event.
	SSID string

	// Channel is the WiFi channel on which the attack was observed.
	Channel int

	// RSSI is the signal strength of the attacking frame(s) in dBm.
	RSSI int

	// FrameCount is the number of frames observed in the detection window.
	FrameCount int

	// Duration is the duration of the observed attack.
	Duration time.Duration

	// Metadata holds arbitrary rule-specific key-value data.
	// Must not be mutated after the event is returned from Rule.Process().
	Metadata map[string]any

	// Description is a human-readable summary of the event.
	Description string
}

// NewEvent creates a new SecurityEvent with the given timestamp, event type, and severity.
// The Metadata map is initialized to an empty map.
func NewEvent(timestamp time.Time, eventType string, severity Severity) *SecurityEvent {
	return &SecurityEvent{
		Timestamp: timestamp,
		EventType: eventType,
		Severity:  severity,
		Metadata:  make(map[string]any),
	}
}

// String returns a human-readable summary of the event.
func (e *SecurityEvent) String() string {
	return fmt.Sprintf("[%s] %s: %s (src=%s, channel=%d)",
		e.Severity.String(), e.EventType, e.Description, e.SrcMAC, e.Channel)
}
