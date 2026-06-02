package capture

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
)

// ErrHoppingDisabled is returned by NewChannelHopper when channel hopping is disabled.
var ErrHoppingDisabled = errors.New("channel hopping is disabled")

// consecutiveFailuresThreshold is the number of consecutive failed channel
// switches after which the hopper enters exponential backoff mode.
const consecutiveFailuresThreshold = 5

// maxBackoffDwell caps the dwell time during backoff to prevent unbounded
// growth on permanently broken interfaces.
const maxBackoffDwell = 30 * time.Second

// channelEntry represents a WiFi channel with its associated dwell time.
type channelEntry struct {
	channel int
	dwell   time.Duration
}

// ChannelHopper manages channel rotation for WiFi capture across multiple
// frequency bands with configurable dwell times and weighted strategies.
type ChannelHopper struct {
	chs []channelEntry
	idx int
}

// NewChannelHopper creates a ChannelHopper from the given configuration.
// It builds the channel list from 2.4 GHz and optionally 5 GHz channels,
// applying weighted dwell time multipliers to primary channels.
//
// Slice ownership: the returned hopper does not retain references to the
// caller's PrimaryChannels/Channels2GHz/Channels5GHz slices. All needed data
// is copied into an independent internal slice.
func NewChannelHopper(cfg *config.ChannelHoppingConfig) (*ChannelHopper, error) {
	if !cfg.Enabled {
		return nil, ErrHoppingDisabled
	}

	// Defensive copy: PrimaryChannels is read multiple times below, and we
	// want to ensure the hopper does not share ownership with the caller.
	primary := append([]int(nil), cfg.WeightedDwell.PrimaryChannels...)

	var entries []channelEntry

	// Add 2.4 GHz channels.
	for _, ch := range cfg.Channels2GHz {
		dwell := cfg.Dwell
		if cfg.WeightedDwell.Enabled && slices.Contains(primary, ch) {
			dwell = time.Duration(float64(dwell) * cfg.WeightedDwell.Multiplier)
		}
		entries = append(entries, channelEntry{channel: ch, dwell: dwell})
	}

	// Add 5 GHz channels if enabled.
	if cfg.Include5GHz {
		for _, ch := range cfg.Channels5GHz {
			entries = append(entries, channelEntry{channel: ch, dwell: cfg.Dwell})
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("no channels configured for hopping")
	}

	return &ChannelHopper{
		chs: entries,
	}, nil
}

// Reset starts the channel list from the beginning.
func (h *ChannelHopper) Reset() {
	h.idx = 0
}

// Next returns the next channel number and its dwell time.
func (h *ChannelHopper) Next() (int, time.Duration) {
	entry := h.chs[h.idx]
	h.idx = (h.idx + 1) % len(h.chs)
	return entry.channel, entry.dwell
}

// ChannelCount returns the number of channels in the hopping list.
func (h *ChannelHopper) ChannelCount() int {
	return len(h.chs)
}

// Run executes channel hopping in a loop, calling setFn for each channel change.
// It blocks until ctx is canceled.
//
// Failure handling: on consecutive setFn errors beyond
// consecutiveFailuresThreshold, the hopper enters exponential backoff,
// doubling the effective dwell time up to maxBackoffDwell. This prevents
// log flooding and reduces load on a broken interface. The first successful
// switch resets both the failure counter and the backoff multiplier.
func (h *ChannelHopper) Run(ctx context.Context, setFn func(channel int) error) {
	h.Reset()
	var consecutiveFailures int
	var backoff time.Duration // 0 = no backoff active
	for {
		channel, dwell := h.Next()

		err := setFn(channel)
		switch {
		case err != nil:
			consecutiveFailures++
			if consecutiveFailures >= consecutiveFailuresThreshold {
				if backoff == 0 {
					backoff = dwell
				}
				backoff = min(backoff*2, maxBackoffDwell)
				dwell = backoff
				slog.Error("channel hop failing repeatedly; backing off",
					"consecutive_failures", consecutiveFailures,
					"channel", channel,
					"backoff", backoff,
					"error", err,
				)
			} else {
				slog.Warn("channel hop failed, skipping channel",
					"channel", channel,
					"error", err,
				)
			}
		default:
			if backoff != 0 || consecutiveFailures > 0 {
				slog.Info("channel hop recovered",
					"channel", channel,
				)
			}
			consecutiveFailures = 0
			backoff = 0
		}

		timer := time.NewTimer(dwell)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			// continue to next channel
		}
	}
}
