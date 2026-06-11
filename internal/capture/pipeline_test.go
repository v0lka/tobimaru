package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
		t.Errorf("got first channel %d, want 1", visited[0])
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

func (m *mockMonitor) IsSupported() bool                                   { return m.supported }
func (m *mockMonitor) EnableMonitor(_ context.Context, _ string) error     { return m.enableErr }
func (m *mockMonitor) DisableMonitor(_ context.Context, _ string) error    { return m.disableErr }
func (m *mockMonitor) SetChannel(_ context.Context, _ string, _ int) error { return m.setChanErr }
func (m *mockMonitor) SupportedChannels(_ context.Context, _ string) ([]int, error) {
	return nil, nil
}

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
		t.Errorf("got MaxChannels %d, want 14", got.MaxChannels)
	}
}

func TestLogCapabilities(t *testing.T) {
	logger := slog.Default()
	// logCapabilities should not panic with any combination of capabilities.
	caps := platform.Capabilities{
		MonitorMode:    true,
		FrameInjection: false,
		ChannelHopping: true,
		MaxChannels:    14,
		SlowHopping:    true,
		SingleAdapter:  true,
	}
	logCapabilities(logger, caps)

	// Also test with frame injection available.
	caps.FrameInjection = true
	logCapabilities(logger, caps)
}

func TestPipelineStopSupported(t *testing.T) {
	mock := &mockMonitor{supported: true}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
		logger:  slog.Default(),
	}

	// Stop should not panic.
	if err := p.Stop(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPipelineStopUnsupported(t *testing.T) {
	mock := &mockMonitor{supported: false}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
		logger:  slog.Default(),
	}

	// Stop on unsupported platform should not panic.
	if err := p.Stop(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPipelineStopDisableError(t *testing.T) {
	mock := &mockMonitor{supported: true, disableErr: errors.New("disable failed")}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
		logger:  slog.Default(),
	}

	// Stop should return error but not panic.
	if err := p.Stop(t.Context()); err == nil {
		t.Fatal("got nil, want error from Stop")
	}
}

func TestPipelineStartNotSupported(t *testing.T) {
	mock := &mockMonitor{supported: false}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
		logger:  slog.Default(),
	}

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for unsupported platform")
	}
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("got %v, want ErrNotSupported", err)
	}
}

func TestPipelineStartEnableMonitorError(t *testing.T) {
	mock := &mockMonitor{supported: true, enableErr: errors.New("enable failed")}
	p := &Pipeline{
		config:  &config.Config{Monitor: config.MonitorConfig{Interface: "en0"}},
		monitor: mock,
		frames:  make(chan *parser.ParsedFrame, 1),
		logger:  slog.Default(),
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
		logger:  slog.Default(),
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
				Snaplen:         65535,
				BufferSize:      2097152,
				Timeout:         100 * time.Millisecond,
				FrameBufferSize: 1024,
			},
			ChannelHopping: config.ChannelHoppingConfig{
				Enabled:      true,
				Dwell:        300 * time.Millisecond,
				Channels2GHz: []int{1, 6, 11},
			},
		},
	}

	p, err := NewPipeline(cfg, slog.Default())
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

func TestPick(t *testing.T) {
	if got := pick(true, "a", "b"); got != "a" {
		t.Errorf("pick(true) = %q, want %q", got, "a")
	}
	if got := pick(false, "a", "b"); got != "b" {
		t.Errorf("pick(false) = %q, want %q", got, "b")
	}
}

func TestFilterBand(t *testing.T) {
	channels := []int{1, 6, 11, 36, 48, 149, 161}
	got := filterBand(channels, 1, 14)
	if len(got) != 3 {
		t.Errorf("expected 3 channels in 2.4 GHz band, got %d: %v", len(got), got)
	}
	got = filterBand(channels, 36, 200)
	if len(got) != 4 {
		t.Errorf("expected 4 channels in 5 GHz band, got %d: %v", len(got), got)
	}
	got = filterBand([]int{}, 1, 14)
	if len(got) != 0 {
		t.Errorf("expected 0 channels for empty input, got %d", len(got))
	}
}

func TestIntersectChannels(t *testing.T) {
	configured := []int{1, 6, 11, 36, 48}
	supported := []int{1, 6, 36, 149}
	got := intersectChannels(configured, supported)
	if len(got) != 3 {
		t.Errorf("expected 3 intersecting channels, got %d: %v", len(got), got)
	}
	// Empty inputs.
	if got := intersectChannels(nil, supported); got != nil {
		t.Errorf("nil configured should return nil, got %v", got)
	}
	if got := intersectChannels(configured, nil); len(got) != 5 {
		t.Errorf("nil supported should return all configured, got %v", got)
	}
}

func TestPipelineCurrentChannel_NoHopper(t *testing.T) {
	p := &Pipeline{config: &config.Config{}}
	if ch := p.CurrentChannel(); ch != 0 {
		t.Errorf("expected 0 without hopper, got %d", ch)
	}
}

func TestPipelineCurrentChannel_WithHopper(t *testing.T) {
	hopper, err := NewChannelHopper(&config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        100 * time.Millisecond,
		Channels2GHz: []int{1, 6},
	})
	if err != nil {
		t.Fatalf("NewChannelHopper: %v", err)
	}
	p := &Pipeline{
		config: &config.Config{},
		hopper: hopper,
	}
	// Before Next is called, CurrentChannel returns 0.
	if ch := p.CurrentChannel(); ch != 0 {
		t.Errorf("expected 0 before first hop, got %d", ch)
	}
	// After Next, it reflects the last channel.
	hopper.Next()
	if ch := p.CurrentChannel(); ch != 1 {
		t.Errorf("expected 1 after first hop, got %d", ch)
	}
}

func TestLogCapabilities_NoFrameInjection(t *testing.T) {
	logger := slog.Default()
	caps := platform.Capabilities{
		MonitorMode:    true,
		FrameInjection: false,
		ChannelHopping: true,
		MaxChannels:    14,
	}
	logCapabilities(logger, caps) // should log "not available" message
}

func TestLogCapabilities_WithLimitations(t *testing.T) {
	logger := slog.Default()
	caps := platform.Capabilities{
		MonitorMode:    true,
		FrameInjection: false,
		ChannelHopping: false,
		MaxChannels:    0,
		SlowHopping:    true,
		SingleAdapter:  true,
	}
	logCapabilities(logger, caps) // should log limitation warnings
}

// buildMinimalDot11Packet returns a valid Radiotap+Dot11 Beacon packet.
func buildMinimalDot11Packet(t *testing.T) gopacket.Packet {
	t.Helper()
	var buf bytes.Buffer
	// Radiotap (8 bytes, no fields).
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(8))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	// Dot11 beacon (24 bytes): type=Mgmt, subtype=Beacon=0x08.
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0080)) // FC
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))      // Duration
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})       // DA (broadcast for beacon)
	buf.Write([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})       // SA (== BSSID for beacon)
	buf.Write([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})       // BSSID
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))      // Seq
	// Beacon body: timestamp(8) + interval(2) + flags(2).
	body := make([]byte, 12)
	binary.LittleEndian.PutUint16(body[8:10], 100) // beacon interval
	buf.Write(body)
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeIEEE80211Radio, gopacket.Default)
}

func TestSafeParse(t *testing.T) {
	// Valid 802.11 packet should parse without error.
	pkt := buildMinimalDot11Packet(t)
	frame, err := safeParse(pkt)
	if err != nil {
		t.Fatalf("safeParse returned error: %v", err)
	}
	if frame == nil {
		t.Fatal("expected non-nil frame")
	}
	if frame.FrameType != parser.FrameTypeBeacon {
		t.Errorf("got %v, want FrameTypeBeacon", frame.FrameType)
	}

	// Non-802.11 packet should return error, not panic.
	badPkt := gopacket.NewPacket([]byte{0x00, 0x01, 0x02}, layers.LinkTypeEthernet, gopacket.Default)
	frame2, err2 := safeParse(badPkt)
	if err2 == nil {
		t.Error("expected error for non-Dot11 packet")
	}
	if frame2 != nil {
		t.Error("expected nil frame for parse error")
	}
}
