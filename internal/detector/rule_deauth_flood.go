package detector

import (
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

type DeauthFloodRule struct {
	rule *floodRule
}

func (r *DeauthFloodRule) Name() string {
	return "deauth_flood"
}

func (r *DeauthFloodRule) Init(cfg config.DetectionConfig) error {
	threshold := cfg.DeauthFlood.Threshold
	window := cfg.DeauthFlood.Window

	if threshold <= 0 {
		threshold = config.DefaultDeauthFloodThreshold
	}
	if window <= 0 {
		window = config.DefaultDeauthFloodWindow
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

func (r *DeauthFloodRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	return r.rule.process(frame)
}
