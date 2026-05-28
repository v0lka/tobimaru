package capture

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
)

// channelEntry represents a WiFi channel with its associated dwell time.
type channelEntry struct {
	channel int
	dwell   time.Duration
}

// ChannelHopper manages channel rotation for WiFi capture across multiple
// frequency bands with configurable dwell times and weighted strategies.
type ChannelHopper struct {
	cfg config.ChannelHoppingConfig
	chs []channelEntry
	idx int
}

// NewChannelHopper creates a ChannelHopper from the given configuration.
// It builds the channel list from 2.4 GHz and optionally 5 GHz channels,
// applying weighted dwell time multipliers to primary channels.
func NewChannelHopper(cfg *config.ChannelHoppingConfig) (*ChannelHopper, error) {
	if !cfg.Enabled {
		return nil, errors.New("channel hopping is disabled")
	}

	var entries []channelEntry

	// Add 2.4 GHz channels.
	for _, ch := range cfg.Channels2GHz {
		dwell := cfg.Dwell
		if cfg.WeightedDwell.Enabled {
			if slices.Contains(cfg.WeightedDwell.PrimaryChannels, ch) {
				dwell = time.Duration(float64(dwell) * cfg.WeightedDwell.Multiplier)
			}
		}
		entries = append(entries, channelEntry{channel: ch, dwell: dwell})
	}

	// Add 5 GHz channels if enabled.
	if cfg.Include5GHz {
		for _, ch := range cfg.Channels5GHz {
			dwell := cfg.Dwell
			entries = append(entries, channelEntry{channel: ch, dwell: dwell})
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("no channels configured for hopping")
	}

	return &ChannelHopper{
		cfg: *cfg,
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
func (h *ChannelHopper) Run(ctx context.Context, setFn func(channel int) error) {
	h.Reset()
	for {
		channel, dwell := h.Next()

		if err := setFn(channel); err != nil {
			slog.Warn("channel hop failed, skipping channel",
				"channel", channel,
				"error", err,
			)
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
