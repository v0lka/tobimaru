package capture

import (
	"errors"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
)

func TestNewChannelHopper(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        100 * time.Millisecond,
		Channels2GHz: []int{1, 6, 11},
		Include5GHz:  false,
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hopper.ChannelCount() != 3 {
		t.Errorf("expected 3 channels, got %d", hopper.ChannelCount())
	}
}

func TestChannelHopperWeightedDwell(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        100 * time.Millisecond,
		Channels2GHz: []int{1, 2, 6, 11},
		WeightedDwell: config.WeightedDwellConfig{
			Enabled:         true,
			PrimaryChannels: []int{6, 11},
			Multiplier:      3.0,
		},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Iterate and check dwell times.
	for range 4 {
		ch, dwell := hopper.Next()
		switch ch {
		case 1, 2:
			if dwell != 100*time.Millisecond {
				t.Errorf("channel %d: expected dwell 100ms, got %v", ch, dwell)
			}
		case 6, 11:
			if dwell != 300*time.Millisecond {
				t.Errorf("channel %d: expected dwell 300ms, got %v", ch, dwell)
			}
		}
	}
}

func TestChannelHopperDisabled(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled: false,
	}
	_, err := NewChannelHopper(&cfg)
	if err == nil {
		t.Fatal("expected error for disabled hopper")
	}
	if !errors.Is(err, ErrHoppingDisabled) {
		t.Errorf("expected ErrHoppingDisabled, got %v", err)
	}
}

func TestChannelHopperNoChannels(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Channels2GHz: []int{},
	}
	_, err := NewChannelHopper(&cfg)
	if err == nil {
		t.Fatal("expected error for no channels")
	}
}

func TestChannelHopperWrapAround(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        1,
		Channels2GHz: []int{1, 6},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ch1, _ := hopper.Next()
	ch2, _ := hopper.Next()
	ch3, _ := hopper.Next() // should wrap

	if ch1 != 1 || ch2 != 6 || ch3 != 1 {
		t.Errorf("expected [1, 6, 1], got [%d, %d, %d]", ch1, ch2, ch3)
	}
}

func TestChannelHopperWith5GHz(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        1,
		Channels2GHz: []int{1, 6},
		Channels5GHz: []int{36, 40},
		Include5GHz:  true,
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hopper.ChannelCount() != 4 {
		t.Errorf("expected 4 channels, got %d", hopper.ChannelCount())
	}

	// Verify all channels are present.
	seen := make(map[int]bool)
	for range 4 {
		ch, _ := hopper.Next()
		seen[ch] = true
	}
	for _, ch := range []int{1, 6, 36, 40} {
		if !seen[ch] {
			t.Errorf("channel %d not seen in iteration", ch)
		}
	}
}

func TestChannelHopperReset(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        1,
		Channels2GHz: []int{1, 6, 11},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hopper.Next() // skip 1
	hopper.Next() // skip 6
	hopper.Reset()
	ch, _ := hopper.Next()
	if ch != 1 {
		t.Errorf("expected channel 1 after reset, got %d", ch)
	}
}
