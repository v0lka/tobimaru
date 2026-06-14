package state

import (
	"net"
	"strings"
	"sync"
	"time"
)

// WhitelistEntry source values.
const (
	// WhitelistSourceManual marks an entry that was added by an operator.
	WhitelistSourceManual = "manual"
	// WhitelistSourceAutoLearning marks an entry produced by auto-learning.
	WhitelistSourceAutoLearning = "auto_learning"
)

// WhitelistEntry represents a trusted device.
type WhitelistEntry struct {
	MAC       net.HardwareAddr
	SSID      string // optional: only whitelist for this SSID
	Comment   string
	Source    string // WhitelistSourceManual or WhitelistSourceAutoLearning
	CreatedAt time.Time
}

// BlacklistEntry represents a known-bad device.
type BlacklistEntry struct {
	MAC       net.HardwareAddr
	Reason    string
	Comment   string
	CreatedAt time.Time
}

// WhitelistEngine manages whitelist and blacklist with thread-safe CRUD.
type WhitelistEngine struct {
	mu        sync.RWMutex
	whitelist map[string]*WhitelistEntry // key: MAC.String() (uppercase)
	blacklist map[string]*BlacklistEntry
}

// NewWhitelistEngine creates a new empty whitelist/blacklist engine.
func NewWhitelistEngine() *WhitelistEngine {
	return &WhitelistEngine{
		whitelist: make(map[string]*WhitelistEntry),
		blacklist: make(map[string]*BlacklistEntry),
	}
}

// AddWhitelist adds or updates a whitelist entry.
func (w *WhitelistEngine) AddWhitelist(entry *WhitelistEntry) {
	if entry == nil || entry.MAC == nil {
		return
	}
	key := normalizeMAC(entry.MAC)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.whitelist[key] = entry
}

// RemoveWhitelist removes a MAC from the whitelist.
func (w *WhitelistEngine) RemoveWhitelist(mac net.HardwareAddr) {
	if mac == nil {
		return
	}
	key := normalizeMAC(mac)

	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.whitelist, key)
}

// IsWhitelisted checks if a MAC is in the whitelist.
func (w *WhitelistEngine) IsWhitelisted(mac net.HardwareAddr) bool {
	if mac == nil {
		return false
	}
	key := normalizeMAC(mac)

	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.whitelist[key]
	return ok
}

// ListWhitelist returns all whitelist entries.
func (w *WhitelistEngine) ListWhitelist() []*WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]*WhitelistEntry, 0, len(w.whitelist))
	for _, e := range w.whitelist {
		result = append(result, e)
	}
	return result
}

// AddBlacklist adds or updates a blacklist entry.
func (w *WhitelistEngine) AddBlacklist(entry *BlacklistEntry) {
	if entry == nil || entry.MAC == nil {
		return
	}
	key := normalizeMAC(entry.MAC)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.blacklist[key] = entry
}

// RemoveBlacklist removes a MAC from the blacklist.
func (w *WhitelistEngine) RemoveBlacklist(mac net.HardwareAddr) {
	if mac == nil {
		return
	}
	key := normalizeMAC(mac)

	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.blacklist, key)
}

// IsBlacklisted checks if a MAC is in the blacklist.
func (w *WhitelistEngine) IsBlacklisted(mac net.HardwareAddr) bool {
	if mac == nil {
		return false
	}
	key := normalizeMAC(mac)

	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.blacklist[key]
	return ok
}

// ListBlacklist returns all blacklist entries.
func (w *WhitelistEngine) ListBlacklist() []*BlacklistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]*BlacklistEntry, 0, len(w.blacklist))
	for _, e := range w.blacklist {
		result = append(result, e)
	}
	return result
}

// LoadFromStorage populates in-memory state from persisted data.
func (w *WhitelistEngine) LoadFromStorage(wl []*WhitelistEntry, bl []*BlacklistEntry) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, entry := range wl {
		if entry != nil && entry.MAC != nil {
			w.whitelist[normalizeMAC(entry.MAC)] = entry
		}
	}
	for _, entry := range bl {
		if entry != nil && entry.MAC != nil {
			w.blacklist[normalizeMAC(entry.MAC)] = entry
		}
	}
}

// BulkAddWhitelist adds multiple entries (used by auto-learning).
func (w *WhitelistEngine) BulkAddWhitelist(entries []*WhitelistEntry) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, entry := range entries {
		if entry != nil && entry.MAC != nil {
			w.whitelist[normalizeMAC(entry.MAC)] = entry
		}
	}
}

// WhitelistLen returns the number of whitelist entries.
func (w *WhitelistEngine) WhitelistLen() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.whitelist)
}

// BlacklistLen returns the number of blacklist entries.
func (w *WhitelistEngine) BlacklistLen() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.blacklist)
}

// normalizeMAC returns a consistent uppercase string key for a MAC address.
func normalizeMAC(mac net.HardwareAddr) string {
	return strings.ToUpper(mac.String())
}
