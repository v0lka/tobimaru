package detector

import (
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

// DisassocFloodRule detects disassociation flood attacks.
type DisassocFloodRule struct {
	rule *floodRule
}

// Name returns the rule identifier.
func (r *DisassocFloodRule) Name() string {
	return EventTypeDisassocFlood
}

// Init validates and applies configuration for this rule.
func (r *DisassocFloodRule) Init(cfg config.DetectionConfig) error {
	threshold := cfg.DisassocFlood.Threshold
	window := cfg.DisassocFlood.Window

	if threshold <= 0 {
		return invalidRuleConfig(r.Name(), "threshold must be > 0")
	}

	if window < time.Second {
		return invalidRuleConfig(r.Name(), "window must be >= 1s")
	}

	r.rule = newFloodRule(
		r.Name(),
		parser.FrameTypeDisassoc,
		SeverityCritical,
		threshold,
		window,
	)

	return nil
}

// Process evaluates a parsed 802.11 frame against the disassociation flood detection rule.
func (r *DisassocFloodRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	return r.rule.process(frame)
}
