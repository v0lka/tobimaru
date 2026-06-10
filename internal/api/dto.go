package api

import (
	"net"
	"strings"
	"time"

	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/state"
)

// apDTO is the JSON shape returned for an Access Point.
type apDTO struct {
	BSSID          string    `json:"bssid"`
	SSID           string    `json:"ssid"`
	Hidden         bool      `json:"hidden"`
	Channel        int       `json:"channel"`
	RSSI           int       `json:"rssi"`
	Capability     uint16    `json:"capability"`
	BeaconInterval uint16    `json:"beacon_interval"`
	BeaconCount    uint64    `json:"beacon_count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

func newAPDTO(ap *state.APInfo) apDTO {
	return apDTO{
		BSSID:          macString(ap.BSSID),
		SSID:           ap.SSID,
		Hidden:         ap.Hidden,
		Channel:        ap.Channel,
		RSSI:           ap.RSSI,
		Capability:     ap.Capability,
		BeaconInterval: ap.BeaconInterval,
		BeaconCount:    ap.BeaconCount,
		FirstSeen:      ap.FirstSeen,
		LastSeen:       ap.LastSeen,
	}
}

// clientDTO is the JSON shape returned for a WiFi client.
type clientDTO struct {
	MAC        string    `json:"mac"`
	BSSID      string    `json:"bssid,omitempty"`
	SSID       string    `json:"ssid,omitempty"`
	Channel    int       `json:"channel"`
	RSSI       int       `json:"rssi"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	FrameCount uint64    `json:"frame_count"`
	Associated bool      `json:"associated"`
	ProbeSSIDs []string  `json:"probe_ssids,omitempty"`
}

func newClientDTO(c *state.ClientInfo) clientDTO {
	return clientDTO{
		MAC:        macString(c.MAC),
		BSSID:      macString(c.BSSID),
		SSID:       c.SSID,
		Channel:    c.Channel,
		RSSI:       c.RSSI,
		FirstSeen:  c.FirstSeen,
		LastSeen:   c.LastSeen,
		FrameCount: c.FrameCount,
		Associated: c.Associated,
		ProbeSSIDs: c.ProbeSSIDs,
	}
}

// eventDTO is the JSON shape returned for a security event.
type eventDTO struct {
	Timestamp   time.Time      `json:"timestamp"`
	EventType   string         `json:"event_type"`
	Severity    string         `json:"severity"`
	SrcMAC      string         `json:"src_mac,omitempty"`
	DstMAC      string         `json:"dst_mac,omitempty"`
	BSSID       string         `json:"bssid,omitempty"`
	SSID        string         `json:"ssid,omitempty"`
	Channel     int            `json:"channel"`
	RSSI        int            `json:"rssi"`
	FrameCount  int            `json:"frame_count"`
	DurationMS  int64          `json:"duration_ms"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

func newEventDTO(ev *detector.SecurityEvent) eventDTO {
	return eventDTO{
		Timestamp:   ev.Timestamp,
		EventType:   ev.EventType,
		Severity:    ev.Severity.String(),
		SrcMAC:      macString(ev.SrcMAC),
		DstMAC:      macString(ev.DstMAC),
		BSSID:       macString(ev.BSSID),
		SSID:        ev.SSID,
		Channel:     ev.Channel,
		RSSI:        ev.RSSI,
		FrameCount:  ev.FrameCount,
		DurationMS:  ev.Duration.Milliseconds(),
		Description: ev.Description,
		Metadata:    ev.Metadata,
	}
}

// whitelistDTO is the JSON shape returned for a whitelist entry.
type whitelistDTO struct {
	MAC       string    `json:"mac"`
	SSID      string    `json:"ssid,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

func newWhitelistDTO(e *state.WhitelistEntry) whitelistDTO {
	return whitelistDTO{
		MAC:       macString(e.MAC),
		SSID:      e.SSID,
		Comment:   e.Comment,
		Source:    e.Source,
		CreatedAt: e.CreatedAt,
	}
}

// blacklistDTO is the JSON shape returned for a blacklist entry.
type blacklistDTO struct {
	MAC       string    `json:"mac"`
	Reason    string    `json:"reason,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func newBlacklistDTO(e *state.BlacklistEntry) blacklistDTO {
	return blacklistDTO{
		MAC:       macString(e.MAC),
		Reason:    e.Reason,
		Comment:   e.Comment,
		CreatedAt: e.CreatedAt,
	}
}

// macString returns an upper-case canonical MAC string, or "" for nil.
func macString(mac net.HardwareAddr) string {
	if mac == nil {
		return ""
	}
	return strings.ToUpper(mac.String())
}
