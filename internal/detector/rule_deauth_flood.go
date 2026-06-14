package detector

import (
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

// DeauthFloodRule detects deauthentication flood attacks.
type DeauthFloodRule struct {
	rule *floodRule
}

// Name returns the rule identifier.
func (r *DeauthFloodRule) Name() string {
	return EventTypeDeauthFlood
}

// Init validates and applies configuration for this rule.
func (r *DeauthFloodRule) Init(cfg config.DetectionConfig) error {
	threshold := cfg.DeauthFlood.Threshold
	window := cfg.DeauthFlood.Window

	if threshold <= 0 {
		return invalidRuleConfig(r.Name(), "threshold must be > 0")
	}

	if window < time.Second {
		return invalidRuleConfig(r.Name(), "window must be >= 1s")
	}

	r.rule = newFloodRule(
		r.Name(),
		parser.FrameTypeDeauth,
		SeverityCritical,
		threshold,
		window,
	)

	return nil
}

// Process evaluates a parsed 802.11 frame against the deauthentication flood detection rule.
func (r *DeauthFloodRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	return r.rule.process(frame)
}
