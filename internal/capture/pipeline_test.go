package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/platform"
)

func TestChannelHopperRun(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        10 * time.Millisecond,
		Channels2GHz: []int{1, 6, 11},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var visited []int
	hopper.Run(ctx, func(channel int) error {
		visited = append(visited, channel)
		return nil
	})

	if len(visited) == 0 {
		t.Error("expected at least one channel hop")
	}
	if visited[0] != 1 {
		t.Errorf("expected first channel 1, got %d", visited[0])
	}
}

func TestChannelHopperRunSetFnError(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        10 * time.Millisecond,
		Channels2GHz: []int{1, 6},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	errCount := 0
	hopper.Run(ctx, func(channel int) error {
		errCount++
		return errors.New("channel switch failed")
	})

	// Should continue hopping despite errors.
	if errCount == 0 {
		t.Error("expected at least one channel hop attempt")
	}
}

// mockMonitor implements MonitorModeManager for testing.
type mockMonitor struct {
	supported  bool
	enableErr  error
	disableErr error
	setChanErr error
}

func (m *mockMonitor) IsSupported() bool                { return m.supported }
func (m *mockMonitor) EnableMonitor(_ string) error     { return m.enableErr }
func (m *mockMonitor) DisableMonitor(_ string) error    { return m.disableErr }
func (m *mockMonitor) SetChannel(_ string, _ int) error { return m.setChanErr }

func TestPipelineFrames(t *testing.T) {
	frames := make(chan *parser.ParsedFrame, 10)
	p := &Pipeline{
		frames: frames,
	}

	ch := p.Frames()
	if ch == nil {
		t.Fatal("Frames() returned nil")
	}
}

func TestPipelineCapabilities(t *testing.T) {
	caps := platform.Capabilities{
		MonitorMode:    true,
		ChannelHopping: true,
		MaxChannels:    14,
	}
	p := &Pipeline{
		caps:   caps,
		frames: make(chan *parser.ParsedFrame, 1),
	}

	got := p.Capabilities()
	if got.MonitorMode != true {
		t.Error("expected MonitorMode true")
	}
	if got.MaxChannels != 14 {
		t.Errorf("expected MaxChannels 14, got %d", got.MaxChannels)
	}
}

func TestLogCapabilities(t *testing.T) {
	// logCapabilities should not panic with any combination of capabilities.
	caps := platform.Capabilities{
		MonitorMode:    true,
		FrameInjection: false,
		ChannelHopping: true,
		MaxChannels:    14,
		SlowHopping:    true,
		SingleAdapter:  true,
	}
	logCapabilities(caps)

	// Also test with frame injection available.
	caps.FrameInjection = true
	logCapabilities(caps)
}

func TestPipelineStopSupported(t *testing.T) {
	mock := &mockMonitor{supported: true}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
	}

	// Stop should not panic.
	p.Stop()
}

func TestPipelineStopUnsupported(t *testing.T) {
	mock := &mockMonitor{supported: false}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
	}

	// Stop on unsupported platform should not panic.
	p.Stop()
}

func TestPipelineStopDisableError(t *testing.T) {
	mock := &mockMonitor{supported: true, disableErr: errors.New("disable failed")}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
	}

	// Stop should log error but not panic.
	p.Stop()
}

func TestPipelineStartNotSupported(t *testing.T) {
	mock := &mockMonitor{supported: false}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
	}

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for unsupported platform")
	}
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("expected ErrNotSupported, got: %v", err)
	}
}

func TestPipelineStartEnableMonitorError(t *testing.T) {
	mock := &mockMonitor{supported: true, enableErr: errors.New("enable failed")}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
	}

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for enable failure")
	}
}

func TestErrNotSupported(t *testing.T) {
	if ErrNotSupported.Error() != "monitor mode is not supported on this platform" {
		t.Errorf("unexpected error message: %s", ErrNotSupported.Error())
	}
}

func TestChannelHopperLoop(t *testing.T) {
	mock := &mockMonitor{supported: true}
	hopper, err := NewChannelHopper(&config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        10 * time.Millisecond,
		Channels2GHz: []int{1, 6},
	})
	if err != nil {
		t.Fatalf("NewChannelHopper failed: %v", err)
	}

	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		hopper:  hopper,
		frames:  make(chan *parser.ParsedFrame, 1),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	p.channelHopperLoop(ctx)
}

func TestNewPipelineCreation(t *testing.T) {
	cfg := &config.Config{
		Monitor: config.MonitorConfig{
			Interface: "en0",
			Capture: config.CaptureConfig{
				Snaplen:    65535,
				BufferSize: 2097152,
				Timeout:    100 * time.Millisecond,
			},
			ChannelHopping: config.ChannelHoppingConfig{
				Enabled:      true,
				Dwell:        300 * time.Millisecond,
				Channels2GHz: []int{1, 6, 11},
			},
		},
	}

	p, err := NewPipeline(cfg)
	if err != nil {
		t.Skipf("NewPipeline not available on this system: %v", err)
	}

	caps := p.Capabilities()
	// Verify consistency: if monitor mode is supported, channel hopping should also be enabled.
	if caps.MonitorMode && !caps.ChannelHopping {
		t.Error("ChannelHopping expected to be available when MonitorMode is supported")
	}
	if p.Frames() == nil {
		t.Error("expected non-nil frames channel")
	}
}
