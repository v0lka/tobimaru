package state

import (
	"net"
	"testing"
	"time"
)

func TestAPMap_Update_NewEntry(t *testing.T) {
	m := NewAPMap()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	now := time.Now()

	m.Update(&APInfo{
		BSSID:     bssid,
		SSID:      "TestNet",
		Channel:   6,
		RSSI:      -50,
		FirstSeen: now,
		LastSeen:  now,
	})

	if m.Len() != 1 {
		t.Fatalf("expected 1 AP, got %d", m.Len())
	}

	ap, ok := m.Get(bssid)
	if !ok {
		t.Fatal("expected AP to be found")
	}
	if ap.SSID != "TestNet" {
		t.Errorf("expected SSID 'TestNet', got %q", ap.SSID)
	}
	if ap.Channel != 6 {
		t.Errorf("expected channel 6, got %d", ap.Channel)
	}
}

func TestAPMap_Update_MergeExisting(t *testing.T) {
	m := NewAPMap()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	t1 := time.Now()
	t2 := t1.Add(5 * time.Second)

	m.Update(&APInfo{
		BSSID:     bssid,
		SSID:      "Net1",
		Channel:   1,
		RSSI:      -60,
		FirstSeen: t1,
		LastSeen:  t1,
	})

	m.Update(&APInfo{
		BSSID:    bssid,
		SSID:     "Net1-updated",
		Channel:  11,
		RSSI:     -40,
		LastSeen: t2,
	})

	ap, _ := m.Get(bssid)
	if ap.SSID != "Net1-updated" {
		t.Errorf("expected updated SSID, got %q", ap.SSID)
	}
	if ap.Channel != 11 {
		t.Errorf("expected channel 11, got %d", ap.Channel)
	}
	if ap.RSSI != -40 {
		t.Errorf("expected RSSI -40, got %d", ap.RSSI)
	}
	if !ap.FirstSeen.Equal(t1) {
		t.Error("FirstSeen should be preserved")
	}
}

func TestAPMap_Evict(t *testing.T) {
	m := NewAPMap()
	bssid1, _ := net.ParseMAC("AA:BB:CC:DD:EE:01")
	bssid2, _ := net.ParseMAC("AA:BB:CC:DD:EE:02")
	now := time.Now()

	m.Update(&APInfo{BSSID: bssid1, LastSeen: now.Add(-10 * time.Minute), FirstSeen: now.Add(-20 * time.Minute)})
	m.Update(&APInfo{BSSID: bssid2, LastSeen: now, FirstSeen: now})

	evicted := m.Evict(now.Add(-5 * time.Minute))
	if evicted != 1 {
		t.Fatalf("expected 1 evicted, got %d", evicted)
	}
	if m.Len() != 1 {
		t.Fatalf("expected 1 remaining, got %d", m.Len())
	}
	_, ok := m.Get(bssid1)
	if ok {
		t.Error("expected bssid1 to be evicted")
	}
	_, ok = m.Get(bssid2)
	if !ok {
		t.Error("expected bssid2 to remain")
	}
}

func TestAPMap_Delete(t *testing.T) {
	m := NewAPMap()
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	m.Update(&APInfo{BSSID: bssid, LastSeen: time.Now(), FirstSeen: time.Now()})
	m.Delete(bssid)
	if m.Len() != 0 {
		t.Fatal("expected 0 APs after delete")
	}
}

func TestAPMap_All(t *testing.T) {
	m := NewAPMap()
	bssid1, _ := net.ParseMAC("AA:BB:CC:DD:EE:01")
	bssid2, _ := net.ParseMAC("AA:BB:CC:DD:EE:02")
	now := time.Now()

	m.Update(&APInfo{BSSID: bssid1, SSID: "Net1", FirstSeen: now, LastSeen: now})
	m.Update(&APInfo{BSSID: bssid2, SSID: "Net2", FirstSeen: now, LastSeen: now})

	all := m.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 APs, got %d", len(all))
	}
}

func TestAPMap_NilHandling(t *testing.T) {
	m := NewAPMap()
	// Should not panic on nil.
	m.Update(nil)
	m.Update(&APInfo{BSSID: nil})
	if m.Len() != 0 {
		t.Fatal("expected 0 APs with nil inputs")
	}
}
