package detector

import (
	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

// Rule represents a detection rule that processes 802.11 frames and emits
// security events when an attack pattern is detected.
//
// Rules are pure functions: Process() receives a parsed frame and returns
// a slice of security events. The DetectionEngine handles deduplication,
// channel management, and alert fan-out. Rules must be fast (O(1) amortized),
// must never block or panic, and must not retain the frame pointer after
// Process() returns.
type Rule interface {
	// Name returns a unique, human-readable identifier for this rule
	// (e.g., "deauth_flood", "evil_twin"). Used for logging and as the
	// default EventType string on emitted events.
	Name() string

	// Init is called once at registration time. The rule extracts its
	// specific thresholds and settings from the detection configuration.
	// Returns an error if required configuration is missing or invalid.
	Init(cfg config.DetectionConfig) error

	// Process evaluates a parsed 802.11 frame against this rule's detection
	// logic. Returns zero or more security events if attack patterns are
	// detected. The returned slice may be empty if no attack is detected.
	// The frame pointer must not be retained after Process returns.
	Process(frame *parser.ParsedFrame) []*SecurityEvent
}
