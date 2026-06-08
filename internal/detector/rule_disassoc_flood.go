package detector

import (
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

type DisassocFloodRule struct {
	rule *floodRule
}

func (r *DisassocFloodRule) Name() string {
	return "disassoc_flood"
}

func (r *DisassocFloodRule) Init(cfg config.DetectionConfig) error {
	threshold := cfg.DisassocFlood.Threshold
	window := cfg.DisassocFlood.Window

	if threshold <= 0 {
		threshold = config.DefaultDisassocFloodThreshold
	}
	if window <= 0 {
		window = config.DefaultDisassocFloodWindow
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

func (r *DisassocFloodRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	return r.rule.process(frame)
}
