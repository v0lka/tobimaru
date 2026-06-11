package state

import (
	"net"
	"testing"
	"time"
)

func TestWhitelistEngine_AddAndCheck(t *testing.T) {
	w := NewWhitelistEngine()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")

	w.AddWhitelist(&WhitelistEntry{
		MAC:       mac,
		SSID:      "Net1",
		Source:    "manual",
		CreatedAt: time.Now(),
	})

	if !w.IsWhitelisted(mac) {
		t.Error("expected MAC to be whitelisted")
	}
	if w.WhitelistLen() != 1 {
		t.Errorf("expected 1 entry, got %d", w.WhitelistLen())
	}
}

func TestWhitelistEngine_Remove(t *testing.T) {
	w := NewWhitelistEngine()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")

	w.AddWhitelist(&WhitelistEntry{MAC: mac, Source: "manual", CreatedAt: time.Now()})
	w.RemoveWhitelist(mac)

	if w.IsWhitelisted(mac) {
		t.Error("expected MAC to not be whitelisted after removal")
	}
}

func TestWhitelistEngine_Blacklist(t *testing.T) {
	w := NewWhitelistEngine()
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	w.AddBlacklist(&BlacklistEntry{
		MAC:       mac,
		Reason:    "suspicious",
		CreatedAt: time.Now(),
	})

	if !w.IsBlacklisted(mac) {
		t.Error("expected MAC to be blacklisted")
	}
	if w.BlacklistLen() != 1 {
		t.Errorf("expected 1 blacklist entry, got %d", w.BlacklistLen())
	}

	w.RemoveBlacklist(mac)
	if w.IsBlacklisted(mac) {
		t.Error("expected MAC to not be blacklisted after removal")
	}
}

func TestWhitelistEngine_List(t *testing.T) {
	w := NewWhitelistEngine()
	mac1, _ := net.ParseMAC("11:22:33:44:55:01")
	mac2, _ := net.ParseMAC("11:22:33:44:55:02")

	w.AddWhitelist(&WhitelistEntry{MAC: mac1, Source: "manual", CreatedAt: time.Now()})
	w.AddWhitelist(&WhitelistEntry{MAC: mac2, Source: "auto_learning", CreatedAt: time.Now()})

	list := w.ListWhitelist()
	if len(list) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(list))
	}
}

func TestWhitelistEngine_ListBlacklist(t *testing.T) {
	w := NewWhitelistEngine()
	mac1, _ := net.ParseMAC("AA:BB:CC:DD:EE:01")
	mac2, _ := net.ParseMAC("AA:BB:CC:DD:EE:02")

	w.AddBlacklist(&BlacklistEntry{MAC: mac1, Reason: "suspicious", CreatedAt: time.Now()})
	w.AddBlacklist(&BlacklistEntry{MAC: mac2, Reason: "manual", CreatedAt: time.Now()})

	list := w.ListBlacklist()
	if len(list) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(list))
	}

	// Empty list should return empty slice, not nil.
	w2 := NewWhitelistEngine()
	emptyList := w2.ListBlacklist()
	if len(emptyList) != 0 {
		t.Errorf("expected empty list, got %d", len(emptyList))
	}
}

func TestWhitelistEngine_BulkAdd(t *testing.T) {
	w := NewWhitelistEngine()
	mac1, _ := net.ParseMAC("11:22:33:44:55:01")
	mac2, _ := net.ParseMAC("11:22:33:44:55:02")

	entries := []*WhitelistEntry{
		{MAC: mac1, Source: "auto_learning", CreatedAt: time.Now()},
		{MAC: mac2, Source: "auto_learning", CreatedAt: time.Now()},
	}

	w.BulkAddWhitelist(entries)
	if w.WhitelistLen() != 2 {
		t.Fatalf("expected 2 entries, got %d", w.WhitelistLen())
	}
}

func TestWhitelistEngine_LoadFromStorage(t *testing.T) {
	w := NewWhitelistEngine()
	mac1, _ := net.ParseMAC("11:22:33:44:55:01")
	mac2, _ := net.ParseMAC("AA:BB:CC:DD:EE:01")

	wl := []*WhitelistEntry{{MAC: mac1, Source: "manual", CreatedAt: time.Now()}}
	bl := []*BlacklistEntry{{MAC: mac2, Reason: "bad", CreatedAt: time.Now()}}

	w.LoadFromStorage(wl, bl)

	if !w.IsWhitelisted(mac1) {
		t.Error("expected mac1 to be whitelisted")
	}
	if !w.IsBlacklisted(mac2) {
		t.Error("expected mac2 to be blacklisted")
	}
}

func TestWhitelistEngine_NilHandling(t *testing.T) {
	w := NewWhitelistEngine()
	// Should not panic.
	w.AddWhitelist(nil)
	w.AddWhitelist(&WhitelistEntry{MAC: nil})
	w.RemoveWhitelist(nil)
	w.AddBlacklist(nil)
	w.RemoveBlacklist(nil)

	if w.IsWhitelisted(nil) {
		t.Error("nil should not be whitelisted")
	}
	if w.IsBlacklisted(nil) {
		t.Error("nil should not be blacklisted")
	}
}

func TestWhitelistEngine_CaseInsensitive(t *testing.T) {
	w := NewWhitelistEngine()
	macLower, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	macUpper, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	w.AddWhitelist(&WhitelistEntry{MAC: macLower, Source: "manual", CreatedAt: time.Now()})

	if !w.IsWhitelisted(macUpper) {
		t.Error("whitelist lookup should be case-insensitive")
	}
}
