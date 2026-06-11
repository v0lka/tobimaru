package state

import (
	"net"
	"testing"
	"time"
)

func TestClientMap_Update_PreservesFrameCountOnZero(t *testing.T) {
	// Updates from frames that don't carry a counter (e.g. probe requests)
	// pass FrameCount=0; the accumulated counter must not be reset.
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()

	m.Update(&ClientInfo{MAC: mac, FirstSeen: now, LastSeen: now, FrameCount: 7})

	m.Update(&ClientInfo{
		MAC:      mac,
		Channel:  6,
		RSSI:     -55,
		LastSeen: now.Add(time.Second),
		// FrameCount intentionally zero (probe-request style update).
	})

	c, _ := m.Get(mac)
	if c.FrameCount != 7 {
		t.Errorf("expected FrameCount preserved at 7, got %d", c.FrameCount)
	}
}

func TestClientMap_Update_OverwritesFrameCountOnNonZero(t *testing.T) {
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()

	m.Update(&ClientInfo{MAC: mac, FirstSeen: now, LastSeen: now, FrameCount: 3})
	m.Update(&ClientInfo{MAC: mac, LastSeen: now, FrameCount: 11})

	c, _ := m.Get(mac)
	if c.FrameCount != 11 {
		t.Errorf("expected FrameCount overwritten to 11, got %d", c.FrameCount)
	}
}

func TestClientMap_Update_NewEntry(t *testing.T) {
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()

	m.Update(&ClientInfo{
		MAC:       mac,
		SSID:      "TestNet",
		Channel:   6,
		RSSI:      -55,
		FirstSeen: now,
		LastSeen:  now,
	})

	if m.Len() != 1 {
		t.Fatalf("expected 1 client, got %d", m.Len())
	}

	c, ok := m.Get(mac)
	if !ok {
		t.Fatal("expected client to be found")
	}
	if c.SSID != "TestNet" {
		t.Errorf("expected SSID 'TestNet', got %q", c.SSID)
	}
}

func TestClientMap_Update_MergeExisting(t *testing.T) {
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	t1 := time.Now()
	t2 := t1.Add(5 * time.Second)

	m.Update(&ClientInfo{
		MAC:       mac,
		SSID:      "Net1",
		Channel:   1,
		FirstSeen: t1,
		LastSeen:  t1,
	})

	m.Update(&ClientInfo{
		MAC:        mac,
		BSSID:      bssid,
		Channel:    11,
		RSSI:       -30,
		LastSeen:   t2,
		Associated: true,
	})

	c, _ := m.Get(mac)
	if !c.Associated {
		t.Error("expected client to be associated")
	}
	if c.BSSID.String() != bssid.String() {
		t.Error("expected BSSID to be set")
	}
	if c.Channel != 11 {
		t.Errorf("expected channel 11, got %d", c.Channel)
	}
	if !c.FirstSeen.Equal(t1) {
		t.Error("FirstSeen should be preserved")
	}
}

func TestClientMap_Evict(t *testing.T) {
	m := NewClientMap()
	mac1, _ := net.ParseMAC("11:22:33:44:55:01")
	mac2, _ := net.ParseMAC("11:22:33:44:55:02")
	now := time.Now()

	m.Update(&ClientInfo{MAC: mac1, LastSeen: now.Add(-10 * time.Minute), FirstSeen: now.Add(-20 * time.Minute)})
	m.Update(&ClientInfo{MAC: mac2, LastSeen: now, FirstSeen: now})

	evicted := m.Evict(now.Add(-5 * time.Minute))
	if evicted != 1 {
		t.Fatalf("expected 1 evicted, got %d", evicted)
	}
	if m.Len() != 1 {
		t.Fatalf("expected 1 remaining, got %d", m.Len())
	}
}

func TestClientMap_AddProbeSSID(t *testing.T) {
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()

	m.Update(&ClientInfo{MAC: mac, FirstSeen: now, LastSeen: now})

	m.AddProbeSSID(mac, "SSID1")
	m.AddProbeSSID(mac, "SSID2")
	m.AddProbeSSID(mac, "SSID1") // duplicate

	c, _ := m.Get(mac)
	if len(c.ProbeSSIDs) != 2 {
		t.Fatalf("expected 2 probe SSIDs, got %d", len(c.ProbeSSIDs))
	}
}

func TestClientMap_NilHandling(t *testing.T) {
	m := NewClientMap()
	m.Update(nil)
	m.Update(&ClientInfo{MAC: nil})
	if m.Len() != 0 {
		t.Fatal("expected 0 clients with nil inputs")
	}
	m.AddProbeSSID(nil, "test")
	m.AddProbeSSID(net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, "")
}

func TestClientMap_Delete(t *testing.T) {
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()
	m.Update(&ClientInfo{MAC: mac, FirstSeen: now, LastSeen: now})
	if m.Len() != 1 {
		t.Fatalf("expected 1 client, got %d", m.Len())
	}
	m.Delete(mac)
	if m.Len() != 0 {
		t.Errorf("expected 0 clients after delete, got %d", m.Len())
	}
}

func TestClientMap_DeleteNotFound(t *testing.T) {
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	// Delete non-existent — should not panic.
	m.Delete(mac)
	if m.Len() != 0 {
		t.Errorf("expected 0 clients, got %d", m.Len())
	}
}

func TestClientMap_EvictProbeOnly(t *testing.T) {
	m := NewClientMap()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	now := time.Now()
	// Add a probe-only client (no association).
	m.Update(&ClientInfo{
		MAC:       mac,
		FirstSeen: now.Add(-time.Hour),
		LastSeen:  now.Add(-time.Hour),
		ProbeSSIDs: []string{"test"},
	})
	n := m.EvictProbeOnly(now)
	if n != 1 {
		t.Errorf("expected 1 evicted probe-only client, got %d", n)
	}
	if m.Len() != 0 {
		t.Errorf("expected 0 clients after eviction, got %d", m.Len())
	}
}
