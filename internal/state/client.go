package state

import (
	"net"
	"slices"
	"sync"
	"time"
)

// ClientInfo represents a discovered WiFi client device.
type ClientInfo struct {
	MAC        net.HardwareAddr `json:"mac"`
	BSSID      net.HardwareAddr `json:"bssid,omitempty"`
	SSID       string           `json:"ssid,omitempty"`
	Channel    int              `json:"channel"`
	RSSI       int              `json:"rssi"`
	FirstSeen  time.Time        `json:"first_seen"`
	LastSeen   time.Time        `json:"last_seen"`
	FrameCount uint64           `json:"frame_count"`
	Associated bool             `json:"associated"`
	ProbeSSIDs []string         `json:"probe_ssids,omitempty"`
}

// ClientMap is a thread-safe in-memory map of MAC → ClientInfo.
type ClientMap struct {
	mu      sync.RWMutex
	clients map[string]*ClientInfo // key: MAC.String()
}

// NewClientMap creates a new empty client map.
func NewClientMap() *ClientMap {
	return &ClientMap{
		clients: make(map[string]*ClientInfo),
	}
}

// Update inserts or updates a client entry. The key is derived from client.MAC.
func (m *ClientMap) Update(client *ClientInfo) {
	if client == nil || client.MAC == nil {
		return
	}
	key := client.MAC.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.clients[key]
	if !ok {
		m.clients[key] = client
		return
	}

	// Merge fields: preserve FirstSeen, update dynamic fields.
	existing.LastSeen = client.LastSeen
	existing.RSSI = client.RSSI
	existing.Channel = client.Channel
	existing.FrameCount = client.FrameCount

	if client.BSSID != nil {
		existing.BSSID = client.BSSID
	}
	if client.SSID != "" {
		existing.SSID = client.SSID
	}
	if client.Associated {
		existing.Associated = true
	}
}

// Get returns the client info for the given MAC address, if found.
func (m *ClientMap) Get(mac net.HardwareAddr) (*ClientInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.clients[mac.String()]
	return c, ok
}

// All returns a snapshot of all client entries. Each returned *ClientInfo is
// a deep copy and is therefore safe to read or mutate without holding the
// map lock.
func (m *ClientMap) All() []*ClientInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*ClientInfo, 0, len(m.clients))
	for _, c := range m.clients {
		result = append(result, cloneClientInfo(c))
	}
	return result
}

// Delete removes a client entry by MAC address.
func (m *ClientMap) Delete(mac net.HardwareAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, mac.String())
}

// Len returns the number of tracked clients.
func (m *ClientMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

// Evict removes entries with LastSeen before the given cutoff time.
// Returns the number of entries evicted.
func (m *ClientMap) Evict(olderThan time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	evicted := 0
	for key, c := range m.clients {
		if c.LastSeen.Before(olderThan) {
			delete(m.clients, key)
			evicted++
		}
	}
	return evicted
}

// AddProbeSSID adds an SSID to the client's probed SSIDs list if not already present.
func (m *ClientMap) AddProbeSSID(mac net.HardwareAddr, ssid string) {
	if mac == nil || ssid == "" {
		return
	}
	key := mac.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.clients[key]
	if !ok {
		return
	}
	if slices.Contains(c.ProbeSSIDs, ssid) {
		return
	}
	c.ProbeSSIDs = append(c.ProbeSSIDs, ssid)
}

// MarkAssociated atomically marks an existing client as associated and
// updates LastSeen (and BSSID, if provided) under lock. Returns true if
// the client existed.
func (m *ClientMap) MarkAssociated(mac net.HardwareAddr, now time.Time, bssid net.HardwareAddr) bool {
	if mac == nil {
		return false
	}
	key := mac.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.clients[key]
	if !ok {
		return false
	}
	c.Associated = true
	c.LastSeen = now
	if bssid != nil {
		c.BSSID = append(net.HardwareAddr(nil), bssid...)
	}
	return true
}

// MarkDisassociated atomically marks an existing client as disassociated and
// updates LastSeen under lock. Returns true if the client existed.
func (m *ClientMap) MarkDisassociated(mac net.HardwareAddr, now time.Time) bool {
	if mac == nil {
		return false
	}
	key := mac.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.clients[key]
	if !ok {
		return false
	}
	c.Associated = false
	c.LastSeen = now
	return true
}

// IncrementFrame atomically increments FrameCount and updates LastSeen,
// Channel, and BSSID for an existing client under lock. Returns true if
// the client existed.
func (m *ClientMap) IncrementFrame(mac net.HardwareAddr, now time.Time, channel int, bssid net.HardwareAddr) bool {
	if mac == nil {
		return false
	}
	key := mac.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.clients[key]
	if !ok {
		return false
	}
	c.FrameCount++
	c.LastSeen = now
	c.Channel = channel
	if bssid != nil {
		c.BSSID = append(net.HardwareAddr(nil), bssid...)
	}
	return true
}

// cloneClientInfo returns a deep copy of a client entry, including its slice
// fields. Used by All() to avoid leaking pointers to mutable state.
func cloneClientInfo(c *ClientInfo) *ClientInfo {
	if c == nil {
		return nil
	}
	cp := *c
	if c.MAC != nil {
		cp.MAC = append(net.HardwareAddr(nil), c.MAC...)
	}
	if c.BSSID != nil {
		cp.BSSID = append(net.HardwareAddr(nil), c.BSSID...)
	}
	if len(c.ProbeSSIDs) > 0 {
		cp.ProbeSSIDs = append([]string(nil), c.ProbeSSIDs...)
	}
	return &cp
}
