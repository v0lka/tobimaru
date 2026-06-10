package state

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func TestLearningMode_Run(t *testing.T) {
	cfg := config.StateConfig{
		Enabled:       true,
		TTL:           10 * time.Minute,
		SweepInterval: 1 * time.Minute,
	}
	e := NewEngine(cfg, config.WhitelistConfig{}, slog.Default())

	// Populate state with associated clients.
	clientMAC1, _ := net.ParseMAC("11:22:33:44:55:01")
	clientMAC2, _ := net.ParseMAC("11:22:33:44:55:02")
	clientMAC3, _ := net.ParseMAC("11:22:33:44:55:03") // not associated
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: now,
		SrcMAC:    clientMAC1,
		BSSID:     bssid,
		SSID:      "Net1",
		Channel:   6,
	})
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: now,
		SrcMAC:    clientMAC2,
		BSSID:     bssid,
		SSID:      "Net1",
		Channel:   6,
	})
	// Client 3 only probes (not associated).
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeProbeRequest,
		Timestamp: now,
		SrcMAC:    clientMAC3,
		SSID:      "Net1",
		Channel:   6,
	})

	// Run learning with a very short duration.
	lmCfg := config.AutoLearningConfig{
		Enabled:  true,
		Duration: 50 * time.Millisecond,
	}
	lm := NewLearningMode(lmCfg, e, slog.Default())

	// Not active before Run.
	if lm.IsActive() {
		t.Error("expected IsActive=false before Run")
	}

	entries := lm.Run(context.Background())

	// Should only include associated clients.
	if len(entries) != 2 {
		t.Fatalf("expected 2 whitelist entries (associated clients only), got %d", len(entries))
	}

	// Verify whitelist was populated.
	if e.Whitelist().WhitelistLen() != 2 {
		t.Errorf("expected 2 whitelist entries in engine, got %d", e.Whitelist().WhitelistLen())
	}

	for _, entry := range entries {
		if entry.Source != "auto_learning" {
			t.Errorf("expected source 'auto_learning', got %q", entry.Source)
		}
	}
}

func TestLearningMode_Canceled(t *testing.T) {
	cfg := config.StateConfig{
		Enabled:       true,
		TTL:           10 * time.Minute,
		SweepInterval: 1 * time.Minute,
	}
	e := NewEngine(cfg, config.WhitelistConfig{}, slog.Default())

	lmCfg := config.AutoLearningConfig{
		Enabled:  true,
		Duration: 10 * time.Second, // long duration
	}
	lm := NewLearningMode(lmCfg, e, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately.
	cancel()

	entries := lm.Run(ctx)
	if entries != nil {
		t.Errorf("expected nil entries when canceled, got %d", len(entries))
	}
}
