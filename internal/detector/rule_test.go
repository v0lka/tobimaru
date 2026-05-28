package detector

import (
	"errors"
	"testing"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

// mockRule is a Rule implementation used for testing the DetectionEngine.
type mockRule struct {
	name         string
	initErr      error
	events       []*SecurityEvent
	processCalls int
}

func (m *mockRule) Name() string { return m.name }

func (m *mockRule) Init(_ config.DetectionConfig) error { return m.initErr }

func (m *mockRule) Process(_ *parser.ParsedFrame) []*SecurityEvent {
	m.processCalls++
	return m.events
}

func TestRuleInterfaceCompliance(t *testing.T) {
	r := &mockRule{name: "test_rule"}
	var iface Rule = r
	if iface.Name() != "test_rule" {
		t.Errorf("Name() = %q, want %q", iface.Name(), "test_rule")
	}
}

func TestRuleInitError(t *testing.T) {
	r := &mockRule{name: "failing_rule", initErr: errors.New("config missing threshold")}
	err := r.Init(config.DetectionConfig{})
	if err == nil {
		t.Error("Init() should return error")
	}
}

func TestRuleInitSuccess(t *testing.T) {
	r := &mockRule{name: "ok_rule"}
	err := r.Init(config.DetectionConfig{})
	if err != nil {
		t.Errorf("Init() unexpected error: %v", err)
	}
}

func TestRuleProcessEmpty(t *testing.T) {
	r := &mockRule{name: "empty_rule"}
	frames := r.Process(nil)
	// nil is a valid return for "no events" — len(nil) == 0.
	if len(frames) != 0 {
		t.Errorf("Process() should return no events, got %d", len(frames))
	}
}

func TestRuleProcessReturnsEvents(t *testing.T) {
	mockEvents := []*SecurityEvent{
		{EventType: "test_alert", Severity: SeverityWarning},
	}
	r := &mockRule{name: "eventful_rule", events: mockEvents}
	frames := r.Process(nil)
	if len(frames) != 1 {
		t.Errorf("Process() returned %d events, want 1", len(frames))
	}
	if frames[0].EventType != "test_alert" {
		t.Errorf("EventType = %q, want test_alert", frames[0].EventType)
	}
}
