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
func TestEngine_ProcessFrame_AssocResponseSuccess(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	// First create the client via an assoc request.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: now,
		SrcMAC:    clientMAC,
		BSSID:     bssid,
		SSID:      "TestNet",
		Channel:   6,
	})

	// Successful assoc response (status=0).
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocResp,
		Timestamp: now.Add(time.Second),
		DstMAC:    clientMAC,
		BSSID:     bssid,
		Status:    0,
	})

	c, _ := e.Clients().Get(clientMAC)
	if !c.Associated {
		t.Error("expected client to remain associated after successful assoc response")
	}
}

func TestEngine_ProcessFrame_AssocResponseFailed(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	// Create the client.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: now,
		SrcMAC:    clientMAC,
		BSSID:     bssid,
		SSID:      "TestNet",
		Channel:   6,
	})

	// Failed assoc response (status != 0) — should be ignored.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocResp,
		Timestamp: now.Add(time.Second),
		DstMAC:    clientMAC,
		BSSID:     bssid,
		Status:    1,
	})

	c, _ := e.Clients().Get(clientMAC)
	if !c.Associated {
		t.Error("client should still be associated (failed response is ignored)")
	}
}

func TestEngine_ProcessFrame_DataFrameFromDS(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	// AP→client data frame (FromDS=1, ToDS=0). DstMAC=client, SrcMAC=BSSID.
	frame := &parser.ParsedFrame{
		FrameType: parser.FrameTypeData,
		Timestamp: now,
		SrcMAC:    bssid,
		DstMAC:    clientMAC,
		ToDS:      false,
		FromDS:    true,
		Channel:   11,
		RSSI:      -55,
	}

	e.ProcessFrame(frame)

	if e.Clients().Len() != 1 {
		t.Fatalf("expected 1 client, got %d", e.Clients().Len())
	}
	c, _ := e.Clients().Get(clientMAC)
	if c.FrameCount != 1 {
		t.Errorf("expected FrameCount 1, got %d", c.FrameCount)
	}
}

func TestProcessFrame_BeaconNilBSSID(t *testing.T) {
	e := newTestEngine()
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeBeacon,
		Timestamp: time.Now(),
		BSSID:     nil,
		SSID:      "X",
	})
	if e.APs().Len() != 0 {
		t.Error("nil BSSID beacon should be ignored")
	}
}

func TestIsBroadcast(t *testing.T) {
	if isBroadcast(nil) {
		t.Error("nil should not be broadcast")
	}
	shortMAC, _ := net.ParseMAC("aa:bb:cc")
	if isBroadcast(shortMAC) {
		t.Error("short MAC should not be broadcast")
	}
	bcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if !isBroadcast(bcast) {
		t.Error("ff:ff:ff:ff:ff:ff should be broadcast")
	}
	notBcast, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if isBroadcast(notBcast) {
		t.Error("aa:bb:cc:dd:ee:ff should not be broadcast")
	}
}

func TestCopyIEs_NonEmpty(t *testing.T) {
	original := map[uint8][]byte{
		1: {0x01, 0x02},
		3: {0x03},
	}
	cp := copyIEs(original)
	if len(cp) != 2 {
		t.Errorf("expected 2 IEs, got %d", len(cp))
	}
	// Mutate original to verify deep copy.
	original[1][0] = 0xFF
	if cp[1][0] == 0xFF {
		t.Error("copy should be independent of original")
	}
}

func TestCopyIEs_Empty(t *testing.T) {
	if got := copyIEs(nil); got != nil {
		t.Error("copyIEs(nil) should return nil")
	}
	if got := copyIEs(map[uint8][]byte{}); got != nil {
		t.Error("copyIEs(empty) should return nil")
	}
}

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

// TestIsValidBSSID verifies BSSID validation logic.
func TestIsValidBSSID(t *testing.T) {
	// Nil — wrong length.
	if isValidBSSID(nil) {
		t.Error("nil should not be valid BSSID")
	}
	// Wrong length.
	if isValidBSSID(net.HardwareAddr{0x00, 0x11, 0x22}) {
		t.Error("short MAC should not be valid BSSID")
	}
	// Broadcast.
	bcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if isValidBSSID(bcast) {
		t.Error("broadcast should not be valid BSSID")
	}
	// Multicast (bit 0 of first byte = 1).
	mcast, _ := net.ParseMAC("01:00:5e:00:00:01")
	if isValidBSSID(mcast) {
		t.Error("multicast should not be valid BSSID")
	}
	// All-zero.
	zeros, _ := net.ParseMAC("00:00:00:00:00:00")
	if isValidBSSID(zeros) {
		t.Error("all-zero should not be valid BSSID")
	}
	// Valid unicast.
	valid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if !isValidBSSID(valid) {
		t.Error("valid unicast MAC should be valid BSSID")
	}
}

// TestProcessFrame_ProbeResponse verifies probe response processing.
func TestProcessFrame_ProbeResponse(t *testing.T) {
	e := newTestEngine()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeProbeResponse,
		Timestamp: now,
		BSSID:     bssid,
		SSID:      "ResponseNet",
		Channel:   6,
		RSSI:      -50,
	})

	if e.APs().Len() != 1 {
		t.Fatalf("expected 1 AP, got %d", e.APs().Len())
	}
	ap, _ := e.APs().Get(bssid)
	if ap.SSID != "ResponseNet" {
		t.Errorf("expected SSID 'ResponseNet', got %q", ap.SSID)
	}
}

// TestProcessFrame_ProbeResponseNilBSSID verifies nil BSSID is rejected.
func TestProcessFrame_ProbeResponseNilBSSID(t *testing.T) {
	e := newTestEngine()
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeProbeResponse,
		Timestamp: time.Now(),
		BSSID:     nil,
		SSID:      "X",
	})
	if e.APs().Len() != 0 {
		t.Error("nil BSSID probe response should be ignored")
	}
}

// TestProcessFrame_ProbeRequestExistingClient verifies updating an existing client.
func TestProcessFrame_ProbeRequestExistingClient(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()

	// First probe creates the client.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeProbeRequest,
		Timestamp: now,
		SrcMAC:    clientMAC,
		SSID:      "FirstNet",
		Channel:   6,
		RSSI:      -60,
	})

	// Second probe with different SSID updates existing client.
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeProbeRequest,
		Timestamp: now.Add(time.Second),
		SrcMAC:    clientMAC,
		SSID:      "SecondNet",
		Channel:   11,
		RSSI:      -55,
	})

	c, _ := e.Clients().Get(clientMAC)
	if len(c.ProbeSSIDs) != 2 {
		t.Errorf("expected 2 ProbeSSIDs, got %d: %v", len(c.ProbeSSIDs), c.ProbeSSIDs)
	}
	if c.Channel != 11 {
		t.Errorf("expected channel 11, got %d", c.Channel)
	}
	if c.RSSI != -55 {
		t.Errorf("expected RSSI -55, got %d", c.RSSI)
	}
}

// TestProcessFrame_AssocRequestNilSrcMAC verifies nil SrcMAC guard.
func TestProcessFrame_AssocRequestNilSrcMAC(t *testing.T) {
	e := newTestEngine()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocReq,
		Timestamp: time.Now(),
		SrcMAC:    nil,
		BSSID:     bssid,
		SSID:      "TestNet",
	})
	if e.Clients().Len() != 0 {
		t.Error("nil SrcMAC assoc request should be ignored")
	}
}

// TestProcessFrame_AssocResponseNilDstMAC verifies nil DstMAC guard.
func TestProcessFrame_AssocResponseNilDstMAC(t *testing.T) {
	e := newTestEngine()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeAssocResp,
		Timestamp: time.Now(),
		DstMAC:    nil,
		BSSID:     bssid,
		Status:    0,
	})
	// Should not panic — just verify no crash.
}

// TestProcessFrame_DataFrameIBSS verifies IBSS (ToDS=0, FromDS=0) is skipped.
func TestProcessFrame_DataFrameIBSS(t *testing.T) {
	e := newTestEngine()
	clientMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeData,
		Timestamp: time.Now(),
		SrcMAC:    clientMAC,
		DstMAC:    bssid,
		ToDS:      false,
		FromDS:    false,
		Channel:   6,
	})
	if e.Clients().Len() != 0 {
		t.Error("IBSS data frame should be skipped")
	}
}

// TestProcessFrame_DataFrameBroadcastClient verifies broadcast client is skipped.
func TestProcessFrame_DataFrameBroadcastClient(t *testing.T) {
	e := newTestEngine()
	bcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	e.ProcessFrame(&parser.ParsedFrame{
		FrameType: parser.FrameTypeData,
		Timestamp: time.Now(),
		SrcMAC:    bcast,
		DstMAC:    bssid,
		ToDS:      true,
		FromDS:    false,
		Channel:   6,
	})
	if e.Clients().Len() != 0 {
		t.Error("broadcast client data frame should be skipped")
	}
}
