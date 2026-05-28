package capture

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/platform"
)

// Pipeline orchestrates WiFi frame capture, parsing, and distribution to consumers.
// It manages the pcap capture goroutine, channel hopping, and delivers parsed frames
// through a buffered Go channel.
type Pipeline struct {
	config  *config.Config
	monitor MonitorModeManager
	handle  *CaptureHandle
	hopper  *ChannelHopper
	frames  chan *parser.ParsedFrame
	caps    platform.Capabilities
}

// NewPipeline creates a new capture pipeline from the application configuration.
// It initializes the monitor mode manager for the current platform, detects
// platform capabilities, and sets up the channel hopper if enabled.
func NewPipeline(cfg *config.Config) (*Pipeline, error) {
	monitor, err := NewMonitorModeManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor mode manager: %w", err)
	}

	caps := platform.Detect()
	logCapabilities(caps)

	var hopper *ChannelHopper
	if cfg.Monitor.ChannelHopping.Enabled {
		hopCfg := cfg.Monitor.ChannelHopping

		// On platforms with slow channel switching, enforce a minimum dwell time
		// to compensate for the overhead of switching channels.
		if caps.SlowHopping {
			const minDwell = 1 * time.Second
			if hopCfg.Dwell < minDwell {
				slog.Warn("increasing dwell time for slow channel hopping platform",
					"original_dwell", hopCfg.Dwell,
					"enforced_dwell", minDwell,
				)
				hopCfg.Dwell = minDwell
			}
		}

		hopper, err = NewChannelHopper(&hopCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create channel hopper: %w", err)
		}
	}

	return &Pipeline{
		config:  cfg,
		monitor: monitor,
		hopper:  hopper,
		frames:  make(chan *parser.ParsedFrame, 1024),
		caps:    caps,
	}, nil
}

// Capabilities returns the platform capabilities detected at pipeline creation.
func (p *Pipeline) Capabilities() platform.Capabilities {
	return p.caps
}

// logCapabilities logs detected platform capabilities and any limitations.
func logCapabilities(caps platform.Capabilities) {
	slog.Info("platform capabilities",
		"monitor_mode", caps.MonitorMode,
		"frame_injection", caps.FrameInjection,
		"channel_hopping", caps.ChannelHopping,
		"max_channels", caps.MaxChannels,
		"slow_hopping", caps.SlowHopping,
		"single_adapter", caps.SingleAdapter,
	)

	if !caps.FrameInjection {
		slog.Info("active countermeasures (frame injection) are not available on this platform")
	}

	for _, lim := range caps.ReportLimitations() {
		slog.Warn("platform limitation", "detail", lim)
	}
}

// Frames returns the read-only channel of parsed frames. Consumers should range
// over this channel to receive captured and parsed 802.11 frames.
func (p *Pipeline) Frames() <-chan *parser.ParsedFrame {
	return p.frames
}

// Start enables monitor mode on the configured interface, opens the capture
// handle, and starts the capture and channel hopping goroutines. It returns
// immediately; frames are delivered on the channel returned by Frames().
// Call Stop to shut down the pipeline.
func (p *Pipeline) Start(ctx context.Context) error {
	iface := p.config.Monitor.Interface

	if !p.monitor.IsSupported() {
		return fmt.Errorf("%w", ErrNotSupported)
	}

	slog.Info("enabling monitor mode", "interface", iface)
	if err := p.monitor.EnableMonitor(iface); err != nil {
		return fmt.Errorf("failed to enable monitor mode on %s: %w", iface, err)
	}

	ccfg := p.config.Monitor.Capture
	handle, err := OpenCapture(iface, ccfg.Snaplen, *ccfg.Promiscuous, ccfg.Timeout, ccfg.BufferSize)
	if err != nil {
		return fmt.Errorf("failed to open capture on %s: %w", iface, err)
	}
	p.handle = handle

	slog.Info("capture started",
		"interface", iface,
		"snaplen", ccfg.Snaplen,
		"buffer_size", ccfg.BufferSize,
		"channel_hopping", p.config.Monitor.ChannelHopping.Enabled,
	)

	// Start capture goroutine.
	captureCtx, cancel := context.WithCancel(ctx)
	go p.captureLoop(captureCtx, cancel)

	// Start channel hopper goroutine.
	if p.hopper != nil {
		go p.channelHopperLoop(captureCtx)
	}

	// Watch for context cancellation to close the pcap handle,
	// which unblocks the capture goroutine.
	go func() {
		<-captureCtx.Done()
		p.handle.Close()
	}()

	return nil
}

// Stop stops the capture pipeline and restores the interface to managed mode.
func (p *Pipeline) Stop() {
	iface := p.config.Monitor.Interface

	if p.monitor.IsSupported() {
		slog.Info("disabling monitor mode", "interface", iface)
		if err := p.monitor.DisableMonitor(iface); err != nil {
			slog.Error("failed to disable monitor mode", "interface", iface, "error", err)
		}
	}
}

// captureLoop reads packets from the pcap handle, parses them, and sends
// parsed frames to the output channel.
func (p *Pipeline) captureLoop(ctx context.Context, cancel context.CancelFunc) {
	defer cancel()
	defer close(p.frames)

	source := p.handle.PacketSource()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := source.NextPacket()
		if err != nil {
			// Handle closed or encountered an error.
			select {
			case <-ctx.Done():
				return
			default:
				slog.Debug("capture read error", "error", err)
				return
			}
		}

		frame, err := parser.Parse(packet)
		if err != nil {
			slog.Debug("frame parse error", "error", err)
			continue
		}

		if frame.FrameType == parser.FrameTypeUnknown {
			continue
		}

		select {
		case p.frames <- frame:
		case <-ctx.Done():
			return
		}
	}
}

// channelHopperLoop runs the channel hopper, switching channels on the
// monitor interface at the configured intervals.
func (p *Pipeline) channelHopperLoop(ctx context.Context) {
	slog.Info("channel hopper started",
		"channel_count", p.hopper.ChannelCount(),
	)

	p.hopper.Run(ctx, func(channel int) error {
		slog.Debug("hopping to channel", "channel", channel)
		return p.monitor.SetChannel(p.config.Monitor.Interface, channel)
	})
}
