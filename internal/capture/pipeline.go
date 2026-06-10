package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/platform"
)

// Pipeline orchestrates WiFi frame capture, parsing, and distribution to consumers.
// It manages the pcap capture goroutine, channel hopping, and delivers parsed frames
// through a buffered Go channel.
type Pipeline struct {
	config     *config.Config
	monitor    MonitorModeManager
	handle     *CaptureHandle
	hopper     *ChannelHopper
	hopperDone chan struct{}
	frames     chan *parser.ParsedFrame
	caps       platform.Capabilities
	logger     *slog.Logger
}

// NewPipeline creates a new capture pipeline from the application configuration.
// It initializes the monitor mode manager for the current platform, detects
// platform capabilities, and sets up the channel hopper if enabled.
func NewPipeline(cfg *config.Config, logger *slog.Logger) (*Pipeline, error) {
	monitor, err := NewMonitorModeManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor mode manager: %w", err)
	}

	caps := platform.Detect()
	logCapabilities(logger, caps)

	var hopper *ChannelHopper
	if cfg.Monitor.ChannelHopping.Enabled {
		hopCfg := cfg.Monitor.ChannelHopping

		// On platforms with slow channel switching, enforce a minimum dwell time
		// to compensate for the overhead of switching channels.
		if caps.SlowHopping {
			const minDwell = 1 * time.Second
			if hopCfg.Dwell < minDwell {
				logger.Warn("increasing dwell time for slow channel hopping platform",
					"original_dwell", hopCfg.Dwell,
					"enforced_dwell", minDwell,
				)
				hopCfg.Dwell = minDwell
			}
		}

		hopper, err = NewChannelHopper(&hopCfg)
		if err != nil {
			if errors.Is(err, ErrHoppingDisabled) {
				logger.Info("channel hopping disabled; continuing without it")
			} else {
				return nil, fmt.Errorf("failed to create channel hopper: %w", err)
			}
		}
	}

	return &Pipeline{
		config:  cfg,
		monitor: monitor,
		hopper:  hopper,
		frames:  make(chan *parser.ParsedFrame, cfg.Monitor.Capture.FrameBufferSize),
		caps:    caps,
		logger:  logger,
	}, nil
}

// Capabilities returns the platform capabilities detected at pipeline creation.
func (p *Pipeline) Capabilities() platform.Capabilities {
	return p.caps
}

// CurrentChannel returns the channel currently being monitored. When channel
// hopping is enabled it reports the channel last set by the hopper. When
// hopping is disabled it returns 0 (the kernel keeps whatever channel the
// adapter was on at startup, which the daemon does not track).
func (p *Pipeline) CurrentChannel() int {
	if p.hopper == nil {
		return 0
	}
	return p.hopper.CurrentChannel()
}

// logCapabilities logs detected platform capabilities and any limitations.
func logCapabilities(logger *slog.Logger, caps platform.Capabilities) {
	logger.Info("platform capabilities",
		"monitor_mode", caps.MonitorMode,
		"frame_injection", caps.FrameInjection,
		"channel_hopping", caps.ChannelHopping,
		"max_channels", caps.MaxChannels,
		"slow_hopping", caps.SlowHopping,
		"single_adapter", caps.SingleAdapter,
	)

	if !caps.FrameInjection {
		logger.Info("active countermeasures (frame injection) are not available on this platform")
	}

	for _, lim := range caps.ReportLimitations() {
		logger.Warn("platform limitation", "detail", lim)
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

	p.logger.Info("enabling monitor mode", "interface", iface)
	if err := p.monitor.EnableMonitor(ctx, iface); err != nil {
		return fmt.Errorf("failed to enable monitor mode on %s: %w", iface, err)
	}

	ccfg := p.config.Monitor.Capture
	handle, err := OpenCapture(iface, ccfg.Snaplen, *ccfg.Promiscuous, ccfg.Timeout, ccfg.BufferSize)
	if err != nil {
		// Best-effort revert of monitor mode so the interface doesn't stay
		// stuck in a state that breaks the user's network connectivity.
		disableCtx, cancel := context.WithTimeout(ctx, disableMonitorTimeout)
		defer cancel()
		if derr := p.monitor.DisableMonitor(disableCtx, iface); derr != nil {
			p.logger.Warn("failed to revert monitor mode after capture open failure",
				"interface", iface, "error", derr)
		}
		return fmt.Errorf("failed to open capture on %s: %w", iface, err)
	}
	p.handle = handle

	p.logger.Info("capture started",
		"interface", iface,
		"snaplen", ccfg.Snaplen,
		"buffer_size", ccfg.BufferSize,
		"frame_buffer_size", ccfg.FrameBufferSize,
		"channel_hopping", p.config.Monitor.ChannelHopping.Enabled,
	)

	// Start capture goroutine.
	captureCtx, cancel := context.WithCancel(ctx)
	go p.captureLoop(captureCtx, cancel)

	// Start channel hopper goroutine with done signal for clean shutdown ordering.
	if p.hopper != nil {
		p.hopperDone = make(chan struct{})
		go func() {
			p.channelHopperLoop(captureCtx)
			close(p.hopperDone)
		}()
	}

	// Watch for context cancellation to close the pcap handle,
	// which unblocks the capture goroutine.
	go func() {
		<-captureCtx.Done()
		p.handle.Close()
	}()

	return nil
}

// disableMonitorTimeout caps how long Pipeline.Stop waits for the OS-level
// "disable monitor mode" command (iw/airport) to return. Prevents the daemon
// from hanging on a broken or unresponsive interface during shutdown.
const disableMonitorTimeout = 5 * time.Second

// Stop stops the capture pipeline and restores the interface to managed mode.
// The OS-level "disable monitor mode" command runs with disableMonitorTimeout
// to prevent shutdown from hanging on broken interfaces. The caller's ctx
// deadline is respected as an upper bound on the operation.
func (p *Pipeline) Stop(ctx context.Context) error {
	iface := p.config.Monitor.Interface

	// Wait for the channel hopper to finish before disabling monitor mode,
	// ensuring no SetChannel calls are in flight.
	if p.hopperDone != nil {
		<-p.hopperDone
	}

	if !p.monitor.IsSupported() {
		return nil
	}

	p.logger.Info("disabling monitor mode", "interface", iface)
	disableCtx, cancel := context.WithTimeout(ctx, disableMonitorTimeout)
	defer cancel()
	if err := p.monitor.DisableMonitor(disableCtx, iface); err != nil {
		p.logger.Error("failed to disable monitor mode", "interface", iface, "error", err)
		return fmt.Errorf("failed to disable monitor mode on %s: %w", iface, err)
	}
	return nil
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
			// Timeout is expected during normal operation (pcap polling).
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			// Handle closed or encountered an error.
			select {
			case <-ctx.Done():
				return
			default:
				p.logger.Warn("unexpected capture read error", "error", err)
				return
			}
		}

		frame, err := safeParse(packet)
		if err != nil {
			p.logger.Debug("frame parse error", "error", err)
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

// safeParse wraps parser.Parse with panic recovery. A panic during parsing
// (e.g. from a malformed RadioTap header) must not terminate the capture
// loop. The recovered panic is converted into a descriptive error.
func safeParse(packet gopacket.Packet) (frame *parser.ParsedFrame, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic recovered: %v", r)
			frame = nil
		}
	}()
	return parser.Parse(packet)
}

// channelHopperLoop runs the channel hopper, switching channels on the
// monitor interface at the configured intervals.
func (p *Pipeline) channelHopperLoop(ctx context.Context) {
	p.logger.Info("channel hopper started",
		"channel_count", p.hopper.ChannelCount(),
	)

	p.hopper.Run(ctx, func(channel int) error {
		p.logger.Debug("hopping to channel", "channel", channel)
		return p.monitor.SetChannel(ctx, p.config.Monitor.Interface, channel)
	})
}
