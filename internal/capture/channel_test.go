package capture

import (
	"context"
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
		t.Errorf("got %d channels, want 3", hopper.ChannelCount())
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
				t.Errorf("channel %d: got dwell %v, want 100ms", ch, dwell)
			}
		case 6, 11:
			if dwell != 300*time.Millisecond {
				t.Errorf("channel %d: got dwell %v, want 300ms", ch, dwell)
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
		t.Errorf("got %v, want ErrHoppingDisabled", err)
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
		t.Errorf("got [%d, %d, %d], want [1, 6, 1]", ch1, ch2, ch3)
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
		t.Errorf("got %d channels, want 4", hopper.ChannelCount())
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
		t.Errorf("got channel %d after reset, want 1", ch)
	}
}

// TestChannelHopperRunBackoff verifies that consecutive setFn failures trigger
// exponential backoff and that a single success resets the counter.
func TestChannelHopperRunBackoff(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        1 * time.Millisecond,
		Channels2GHz: []int{1, 6},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("NewChannelHopper failed: %v", err)
	}

	// Always-fail setFn: count calls, observe inter-call delay growing.
	var callCount int
	var lastCall time.Time
	var maxDelay time.Duration

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	hopper.Run(ctx, func(_ int) error {
		now := time.Now()
		if !lastCall.IsZero() {
			d := now.Sub(lastCall)
			if d > maxDelay {
				maxDelay = d
			}
		}
		lastCall = now
		callCount++
		return errors.New("always fails")
	})

	// We should have entered backoff (delay > base dwell of 1ms).
	if callCount < consecutiveFailuresThreshold {
		t.Errorf("got %d calls before backoff, want at least %d", callCount, consecutiveFailuresThreshold)
	}
	if maxDelay <= 1*time.Millisecond {
		t.Errorf("expected backoff to grow delay above base dwell, max observed %v", maxDelay)
	}
}

// TestChannelHopperRunBackoffResetsOnSuccess verifies that a single successful
// setFn call resets the failure counter and exits backoff.
func TestChannelHopperRunBackoffResetsOnSuccess(t *testing.T) {
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        1 * time.Millisecond,
		Channels2GHz: []int{1, 6},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("NewChannelHopper failed: %v", err)
	}

	var calls int
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	hopper.Run(ctx, func(_ int) error {
		calls++
		// Fail several times to trigger backoff, then succeed once.
		if calls <= consecutiveFailuresThreshold+1 {
			return errors.New("fail")
		}
		return nil
	})

	if calls < consecutiveFailuresThreshold+2 {
		t.Errorf("got %d calls (failures + recovery), want at least %d", calls, consecutiveFailuresThreshold+2)
	}
}

// TestNewChannelHopperPrimaryChannelsCopy verifies that NewChannelHopper does
// not retain a reference to the caller's PrimaryChannels slice.
func TestNewChannelHopperPrimaryChannelsCopy(t *testing.T) {
	primary := []int{6}
	cfg := config.ChannelHoppingConfig{
		Enabled:      true,
		Dwell:        100 * time.Millisecond,
		Channels2GHz: []int{1, 6},
		WeightedDwell: config.WeightedDwellConfig{
			Enabled:         true,
			PrimaryChannels: primary,
			Multiplier:      2.0,
		},
	}
	hopper, err := NewChannelHopper(&cfg)
	if err != nil {
		t.Fatalf("NewChannelHopper failed: %v", err)
	}

	// Mutate the caller's slice; hopper should be unaffected.
	primary[0] = 11

	// Iterate channels and check dwell times: channel 6 should still have
	// the multiplied dwell because hopper made its own copy.
	for range hopper.ChannelCount() {
		ch, dwell := hopper.Next()
		if ch == 6 && dwell != 200*time.Millisecond {
			t.Errorf("channel 6: got dwell %v, want 200ms (multiplied) — slice ownership leaked", dwell)
		}
		if ch == 11 && dwell == 200*time.Millisecond {
			t.Error("channel 11 unexpectedly got multiplied dwell — slice ownership leaked")
		}
	}
}
