// Package state provides the network state engine that maintains an in-memory
// map of observed Access Points and WiFi clients, with TTL-based eviction.
package state

import (
	"net"
	"sync"
	"time"
)

// APInfo represents a discovered Access Point.
type APInfo struct {
	BSSID          net.HardwareAddr `json:"bssid"`
	SSID           string           `json:"ssid"`
	Channel        int              `json:"channel"`
	RSSI           int              `json:"rssi"`
	Capability     uint16           `json:"capability"`
	BeaconInterval uint16           `json:"beacon_interval"`
	InfoElements   map[uint8][]byte `json:"info_elements,omitempty"`
	FirstSeen      time.Time        `json:"first_seen"`
	LastSeen       time.Time        `json:"last_seen"`
	BeaconCount    uint64           `json:"beacon_count"`
	Hidden         bool             `json:"hidden"`
}

// APMap is a thread-safe in-memory map of BSSID → APInfo.
type APMap struct {
	mu  sync.RWMutex
	aps map[string]*APInfo // key: BSSID.String()
}

// NewAPMap creates a new empty AP map.
func NewAPMap() *APMap {
	return &APMap{
		aps: make(map[string]*APInfo),
	}
}

// Update inserts or updates an AP entry. The key is derived from ap.BSSID.
func (m *APMap) Update(ap *APInfo) {
	if ap == nil || ap.BSSID == nil {
		return
	}
	key := ap.BSSID.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.aps[key]
	if !ok {
		m.aps[key] = ap
		return
	}

	// Merge fields: preserve FirstSeen, update LastSeen and dynamic fields.
	existing.LastSeen = ap.LastSeen
	existing.RSSI = ap.RSSI
	existing.Channel = ap.Channel
	existing.BeaconCount = ap.BeaconCount

	if ap.SSID != "" {
		existing.SSID = ap.SSID
		existing.Hidden = false
	}
	if ap.Capability != 0 {
		existing.Capability = ap.Capability
	}
	if ap.BeaconInterval != 0 {
		existing.BeaconInterval = ap.BeaconInterval
	}
	if len(ap.InfoElements) > 0 {
		existing.InfoElements = ap.InfoElements
	}
}

// Get returns the AP info for the given BSSID, if found.
func (m *APMap) Get(bssid net.HardwareAddr) (*APInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ap, ok := m.aps[bssid.String()]
	return ap, ok
}

// All returns a snapshot of all AP entries. Each returned *APInfo is a deep
// copy and is therefore safe to read or mutate without holding the map lock.
func (m *APMap) All() []*APInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*APInfo, 0, len(m.aps))
	for _, ap := range m.aps {
		result = append(result, cloneAPInfo(ap))
	}
	return result
}

// Delete removes an AP entry by BSSID.
func (m *APMap) Delete(bssid net.HardwareAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.aps, bssid.String())
}

// Len returns the number of tracked APs.
func (m *APMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.aps)
}

// Evict removes entries with LastSeen before the given cutoff time.
// Returns the number of entries evicted.
func (m *APMap) Evict(olderThan time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	evicted := 0
	for key, ap := range m.aps {
		if ap.LastSeen.Before(olderThan) {
			delete(m.aps, key)
			evicted++
		}
	}
	return evicted
}

// UpdateBeacon atomically applies beacon-frame fields to the AP entry under lock.
// If the entry does not exist, it is inserted. Returns true when an existing
// entry was updated, false when a new entry was inserted.
func (m *APMap) UpdateBeacon(
	bssid net.HardwareAddr,
	now time.Time,
	rssi, channel int,
	ssid string,
	ssidPresent bool,
	capability, beaconInterval uint16,
	ies map[uint8][]byte,
) bool {
	if bssid == nil {
		return false
	}
	key := bssid.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	ap, ok := m.aps[key]
	if !ok {
		hidden := ssidPresent && ssid == ""
		m.aps[key] = &APInfo{
			BSSID:          append(net.HardwareAddr(nil), bssid...),
			SSID:           ssid,
			Channel:        channel,
			RSSI:           rssi,
			Capability:     capability,
			BeaconInterval: beaconInterval,
			InfoElements:   copyIEs(ies),
			FirstSeen:      now,
			LastSeen:       now,
			BeaconCount:    1,
			Hidden:         hidden,
		}
		return false
	}

	ap.LastSeen = now
	ap.RSSI = rssi
	ap.Channel = channel
	ap.BeaconCount++
	if ssid != "" {
		ap.SSID = ssid
		ap.Hidden = false
	} else if ssidPresent {
		ap.Hidden = true
	}
	if capability != 0 {
		ap.Capability = capability
	}
	if beaconInterval != 0 {
		ap.BeaconInterval = beaconInterval
	}
	if len(ies) > 0 {
		ap.InfoElements = copyIEs(ies)
	}
	return true
}

// UpdateProbeResponse atomically applies probe-response fields to the AP entry
// under lock. If the entry does not exist, it is inserted. Returns true when
// an existing entry was updated.
func (m *APMap) UpdateProbeResponse(
	bssid net.HardwareAddr,
	now time.Time,
	rssi, channel int,
	ssid string,
	capability, beaconInterval uint16,
	ies map[uint8][]byte,
) bool {
	if bssid == nil {
		return false
	}
	key := bssid.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	ap, ok := m.aps[key]
	if !ok {
		m.aps[key] = &APInfo{
			BSSID:          append(net.HardwareAddr(nil), bssid...),
			SSID:           ssid,
			Channel:        channel,
			RSSI:           rssi,
			Capability:     capability,
			BeaconInterval: beaconInterval,
			InfoElements:   copyIEs(ies),
			FirstSeen:      now,
			LastSeen:       now,
		}
		return false
	}

	ap.LastSeen = now
	ap.RSSI = rssi
	ap.Channel = channel
	if ssid != "" {
		ap.SSID = ssid
		ap.Hidden = false
	}
	if capability != 0 {
		ap.Capability = capability
	}
	if beaconInterval != 0 {
		ap.BeaconInterval = beaconInterval
	}
	if len(ies) > 0 {
		ap.InfoElements = copyIEs(ies)
	}
	return true
}

// cloneAPInfo returns a deep copy of an AP entry, including its slice and
// map fields. Used by All() to avoid leaking pointers to mutable state.
func cloneAPInfo(ap *APInfo) *APInfo {
	if ap == nil {
		return nil
	}
	cp := *ap
	if ap.BSSID != nil {
		cp.BSSID = append(net.HardwareAddr(nil), ap.BSSID...)
	}
	cp.InfoElements = copyIEs(ap.InfoElements)
	return &cp
}
