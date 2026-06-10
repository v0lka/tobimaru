package state

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func newTestEngine() *Engine {
	cfg := config.StateConfig{
		Enabled:       true,
		TTL:           10 * time.Minute,
		SweepInterval: 1 * time.Minute,
	}
	wlCfg := config.WhitelistConfig{}
	return NewEngine(cfg, wlCfg, slog.Default())
}

func TestEngine_ProcessFrame_Beacon(t *testing.T) {
	e := newTestEngine()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	frame := &parser.ParsedFrame{
		FrameType:      parser.FrameTypeBeacon,
		Timestamp:      now,
		BSSID:          bssid,
		SSID:           "TestNetwork",
		SSIDPresent:    true,
		Channel:        6,
		RSSI:           -45,
		Capability:     0x0431,
		BeaconInterval: 100,
	}

	e.ProcessFrame(frame)

	if e.APs().Len() != 1 {
		t.Fatalf("expected 1 AP, got %d", e.APs().Len())
	}

	ap, ok := e.APs().Get(bssid)
	if !ok {
		t.Fatal("expected AP to exist")
	}
	if ap.SSID != "TestNetwork" {
		t.Errorf("expected SSID 'TestNetwork', got %q", ap.SSID)
	}
	if ap.BeaconCount != 1 {
		t.Errorf("expected BeaconCount 1, got %d", ap.BeaconCount)
	}
	if ap.Hidden {
		t.Error("expected Hidden=false")
	}

	// Second beacon should increment count.
	e.ProcessFrame(frame)
	ap, _ = e.APs().Get(bssid)
	if ap.BeaconCount != 2 {
		t.Errorf("expected BeaconCount 2, got %d", ap.BeaconCount)
	}
}

func TestEngine_ProcessFrame_HiddenBeacon(t *testing.T) {
	e := newTestEngine()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	frame := &parser.ParsedFrame{
		FrameType:   parser.FrameTypeBeacon,
		Timestamp:   time.Now(),
		BSSID:       bssid,
		SSID:        "",
		SSIDPresent: true,
		Channel:     1,
	}

	e.ProcessFrame(frame)
	ap, _ := e.APs().Get(bssid)
	if !ap.Hidden {
		t.Error("expected Hidden=true for empty SSID with SSIDPresent")
	}
}

func TestEngine_ProcessFrame_ProbeRequest(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")

	frame := &parser.ParsedFrame{
		FrameType: parser.FrameTypeProbeRequest,
		Timestamp: time.Now(),
		SrcMAC:    clientMAC,
		SSID:      "ProbeSSID",
		Channel:   6,
		RSSI:      -60,
	}

	e.ProcessFrame(frame)

	if e.Clients().Len() != 1 {
		t.Fatalf("expected 1 client, got %d", e.Clients().Len())
	}

	c, _ := e.Clients().Get(clientMAC)
	if len(c.ProbeSSIDs) != 1 || c.ProbeSSIDs[0] != "ProbeSSID" {
		t.Errorf("expected ProbeSSIDs ['ProbeSSID'], got %v", c.ProbeSSIDs)
	}
}

func TestEngine_ProcessFrame_AssocRequest(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	frame := &parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: time.Now(),
		SrcMAC:    clientMAC,
		BSSID:     bssid,
		SSID:      "TestNet",
		Channel:   6,
	}

	e.ProcessFrame(frame)

	c, _ := e.Clients().Get(clientMAC)
	if !c.Associated {
		t.Error("expected client to be associated after assoc request")
	}
	if c.BSSID.String() != bssid.String() {
		t.Error("expected BSSID to be set")
	}
}

func TestEngine_ProcessFrame_DeauthDisassoc(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	// First associate.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: now,
		SrcMAC:    clientMAC,
		BSSID:     bssid,
		SSID:      "TestNet",
		Channel:   6,
	})

	// Then deauth.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeDeauth,
		Timestamp: now.Add(time.Second),
		SrcMAC:    bssid,
		DstMAC:    clientMAC,
		BSSID:     bssid,
	})

	c, _ := e.Clients().Get(clientMAC)
	if c.Associated {
		t.Error("expected client to be disassociated after deauth")
	}
}

func TestEngine_ProcessFrame_DataFrame(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	frame := &parser.ParsedFrame{
		FrameType: parser.FrameTypeData,
		Timestamp: time.Now(),
		SrcMAC:    clientMAC,
		DstMAC:    bssid,
		ToDS:      true,
		FromDS:    false,
		Channel:   6,
		RSSI:      -50,
	}

	e.ProcessFrame(frame)

	if e.Clients().Len() != 1 {
		t.Fatalf("expected 1 client, got %d", e.Clients().Len())
	}
	c, _ := e.Clients().Get(clientMAC)
	if c.FrameCount != 1 {
		t.Errorf("expected FrameCount 1, got %d", c.FrameCount)
	}
	if !c.Associated {
		t.Error("data frame should imply association")
	}
}

func TestEngine_ProcessFrame_Nil(t *testing.T) {
	e := newTestEngine()
	// Should not panic.
	e.ProcessFrame(nil)
}

func TestEngine_Snapshot(t *testing.T) {
	e := newTestEngine()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()

	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeBeacon,
		Timestamp: now,
		BSSID:     bssid,
		SSID:      "Net",
		Channel:   1,
	})
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeProbeRequest,
		Timestamp: now,
		SrcMAC:    mac,
		SSID:      "Net",
		Channel:   1,
	})

	snap := e.Snapshot()
	if len(snap.APs) != 1 {
		t.Errorf("expected 1 AP in snapshot, got %d", len(snap.APs))
	}
	if len(snap.Clients) != 1 {
		t.Errorf("expected 1 client in snapshot, got %d", len(snap.Clients))
	}
}

func TestEngine_RunEviction(t *testing.T) {
	cfg := config.StateConfig{
		Enabled:       true,
		TTL:           50 * time.Millisecond,
		SweepInterval: 20 * time.Millisecond,
	}
	e := NewEngine(cfg, config.WhitelistConfig{}, slog.Default())

	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeBeacon,
		Timestamp: time.Now().Add(-100 * time.Millisecond),
		BSSID:     bssid,
		SSID:      "OldNet",
		Channel:   1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	go e.RunEviction(ctx)

	// Wait for eviction to trigger.
	time.Sleep(100 * time.Millisecond)

	if e.APs().Len() != 0 {
		t.Errorf("expected 0 APs after eviction, got %d", e.APs().Len())
	}
}

// TestEngine_ProcessFrame_DeauthFromClient verifies that a deauth/disassoc
// initiated by the client (client in SrcMAC, AP in DstMAC) marks the client
// as disassociated.
func TestEngine_ProcessFrame_DeauthFromClient(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	// First associate.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: now,
		SrcMAC:    clientMAC,
		BSSID:     bssid,
		SSID:      "TestNet",
		Channel:   6,
	})

	// Client → AP deauth (client in SrcMAC).
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeDisassoc,
		Timestamp: now.Add(time.Second),
		SrcMAC:    clientMAC,
		DstMAC:    bssid,
		BSSID:     bssid,
	})

	c, _ := e.Clients().Get(clientMAC)
	if c.Associated {
		t.Error("expected client to be disassociated after client-initiated deauth")
	}
}

// TestEngine_ConcurrentProcessAndSnapshot verifies that ProcessFrame,
// Snapshot, and RunEviction can run concurrently without data races. Run
// with `-race` to validate.
func TestEngine_ConcurrentProcessAndSnapshot(t *testing.T) {
	cfg := config.StateConfig{
		Enabled:       true,
		TTL:           5 * time.Second,
		SweepInterval: 5 * time.Millisecond,
	}
	e := NewEngine(cfg, config.WhitelistConfig{}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Eviction goroutine.
	wg.Go(func() {
		e.RunEviction(ctx)
	})

	// Producer: hammer the engine with frames covering all process paths.
	wg.Go(func() {
		deadline := time.Now().Add(200 * time.Millisecond)
		for i := 0; time.Now().Before(deadline); i++ {
			bssid := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, byte(i % 8)}
			mac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, byte(i % 8)}
			now := time.Now()

			e.ProcessFrame(&parser.ParsedFrame{
				FrameType:   parser.FrameTypeBeacon,
				Timestamp:   now,
				BSSID:       bssid,
				SSID:        "Net",
				SSIDPresent: true,
				Channel:     6,
				RSSI:        -40,
			})
			e.ProcessFrame(&parser.ParsedFrame{
				FrameType: parser.FrameTypeProbeResponse,
				Timestamp: now,
				BSSID:     bssid,
				SSID:      "Net",
				Channel:   6,
			})
			e.ProcessFrame(&parser.ParsedFrame{
				FrameType: parser.FrameTypeAssocReq,
				Timestamp: now,
				SrcMAC:    mac,
				BSSID:     bssid,
				Channel:   6,
			})
			e.ProcessFrame(&parser.ParsedFrame{
				FrameType: parser.FrameTypeData,
				Timestamp: now,
				SrcMAC:    mac,
				DstMAC:    bssid,
				ToDS:      true,
				Channel:   6,
			})
			e.ProcessFrame(&parser.ParsedFrame{
				FrameType: parser.FrameTypeDeauth,
				Timestamp: now,
				SrcMAC:    bssid,
				DstMAC:    mac,
				BSSID:     bssid,
			})
		}
	})

	// Snapshot reader.
	wg.Go(func() {
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			snap := e.Snapshot()
			// Touch fields to ensure they are real reads, not optimized away.
			for _, ap := range snap.APs {
				_ = ap.LastSeen
				_ = ap.BeaconCount
			}
			for _, c := range snap.Clients {
				_ = c.LastSeen
				_ = c.FrameCount
			}
		}
	})

	// Let workers run, then cancel and wait.
	time.Sleep(200 * time.Millisecond)
	cancel()
	wg.Wait()
}
