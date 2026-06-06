package state

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

// Engine maintains the in-memory network state by consuming parsed frames
// and tracking APs, clients, and their lifecycle.
type Engine struct {
	cfg       config.StateConfig
	aps       *APMap
	clients   *ClientMap
	whitelist *WhitelistEngine
	logger    *slog.Logger
}

// Snapshot holds a point-in-time copy of the network state.
type Snapshot struct {
	Timestamp time.Time
	APs       []*APInfo
	Clients   []*ClientInfo
}

// NewEngine creates a new state engine from configuration.
func NewEngine(cfg config.StateConfig, wlCfg config.WhitelistConfig, logger *slog.Logger) *Engine {
	return &Engine{
		cfg:       cfg,
		aps:       NewAPMap(),
		clients:   NewClientMap(),
		whitelist: NewWhitelistEngine(),
		logger:    logger,
	}
}

// APs returns the AP map.
func (e *Engine) APs() *APMap {
	return e.aps
}

// Clients returns the client map.
func (e *Engine) Clients() *ClientMap {
	return e.clients
}

// Whitelist returns the whitelist engine.
func (e *Engine) Whitelist() *WhitelistEngine {
	return e.whitelist
}

// Snapshot returns a point-in-time copy of APs and clients for persistence.
func (e *Engine) Snapshot() *Snapshot {
	return &Snapshot{
		Timestamp: time.Now(),
		APs:       e.aps.All(),
		Clients:   e.clients.All(),
	}
}

// ProcessFrame updates state based on a single parsed frame.
func (e *Engine) ProcessFrame(frame *parser.ParsedFrame) {
	if frame == nil {
		return
	}

	switch frame.FrameType {
	case parser.FrameTypeBeacon:
		e.processBeacon(frame)
	case parser.FrameTypeProbeResponse:
		e.processProbeResponse(frame)
	case parser.FrameTypeProbeRequest:
		e.processProbeRequest(frame)
	case parser.FrameTypeAssocReq, parser.FrameTypeReassocReq:
		e.processAssocRequest(frame)
	case parser.FrameTypeAssocResp, parser.FrameTypeReassocResp:
		e.processAssocResponse(frame)
	case parser.FrameTypeDeauth, parser.FrameTypeDisassoc:
		e.processDeauthDisassoc(frame)
	case parser.FrameTypeData, parser.FrameTypeQoSData:
		e.processDataFrame(frame)
	case parser.FrameTypeUnknown, parser.FrameTypeAuth, parser.FrameTypeAction,
		parser.FrameTypeCTS, parser.FrameTypeRTS, parser.FrameTypeACK,
		parser.FrameTypeBlockAckReq, parser.FrameTypeBlockAck, parser.FrameTypeNull:
		// Frame types not relevant for state tracking.
	}
}

// RunEviction starts the TTL eviction goroutine. It periodically sweeps
// both AP and client maps, removing entries not observed within the TTL.
// Exits when ctx is canceled.
func (e *Engine) RunEviction(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-e.cfg.TTL)
			apEvicted := e.aps.Evict(cutoff)
			clientEvicted := e.clients.Evict(cutoff)
			if apEvicted > 0 || clientEvicted > 0 {
				e.logger.Debug("state eviction sweep",
					"aps_evicted", apEvicted,
					"clients_evicted", clientEvicted,
					"aps_remaining", e.aps.Len(),
					"clients_remaining", e.clients.Len(),
				)
			}
		}
	}
}

// processBeacon updates the AP map from a beacon frame.
func (e *Engine) processBeacon(frame *parser.ParsedFrame) {
	if frame.BSSID == nil {
		return
	}
	now := frame.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	e.aps.UpdateBeacon(
		frame.BSSID,
		now,
		frame.RSSI,
		frame.Channel,
		frame.SSID,
		frame.SSIDPresent,
		frame.Capability,
		frame.BeaconInterval,
		frame.InfoElements,
	)
}

// processProbeResponse updates the AP map from a probe response.
func (e *Engine) processProbeResponse(frame *parser.ParsedFrame) {
	if frame.BSSID == nil {
		return
	}
	now := frame.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	e.aps.UpdateProbeResponse(
		frame.BSSID,
		now,
		frame.RSSI,
		frame.Channel,
		frame.SSID,
		frame.Capability,
		frame.BeaconInterval,
		frame.InfoElements,
	)
}

// processProbeRequest updates client map from a probe request.
func (e *Engine) processProbeRequest(frame *parser.ParsedFrame) {
	if frame.SrcMAC == nil {
		return
	}
	now := frame.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	_, exists := e.clients.Get(frame.SrcMAC)
	if exists {
		e.clients.Update(&ClientInfo{
			MAC:        frame.SrcMAC,
			Channel:    frame.Channel,
			RSSI:       frame.RSSI,
			LastSeen:   now,
			FrameCount: 0, // will be merged, not overwritten if zero
		})
	} else {
		e.clients.Update(&ClientInfo{
			MAC:       frame.SrcMAC,
			SSID:      frame.SSID,
			Channel:   frame.Channel,
			RSSI:      frame.RSSI,
			FirstSeen: now,
			LastSeen:  now,
		})
	}

	if frame.SSID != "" {
		e.clients.AddProbeSSID(frame.SrcMAC, frame.SSID)
	}
}

// processAssocRequest marks a client as associated with an AP.
func (e *Engine) processAssocRequest(frame *parser.ParsedFrame) {
	if frame.SrcMAC == nil {
		return
	}
	now := frame.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	e.clients.Update(&ClientInfo{
		MAC:        frame.SrcMAC,
		BSSID:      frame.BSSID,
		SSID:       frame.SSID,
		Channel:    frame.Channel,
		RSSI:       frame.RSSI,
		FirstSeen:  now,
		LastSeen:   now,
		Associated: true,
	})
}

// processAssocResponse confirms a client's association (successful response).
func (e *Engine) processAssocResponse(frame *parser.ParsedFrame) {
	// Only process successful associations (status code 0).
	if frame.Status != 0 {
		return
	}
	if frame.DstMAC == nil {
		return
	}
	now := frame.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	e.clients.MarkAssociated(frame.DstMAC, now, frame.BSSID)
}

// processDeauthDisassoc marks a client as disassociated.
func (e *Engine) processDeauthDisassoc(frame *parser.ParsedFrame) {
	// The client being deauthed could be in DstMAC (AP sending to client)
	// or SrcMAC (client sending to AP). We handle both.
	now := frame.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	if frame.DstMAC != nil && !isBroadcast(frame.DstMAC) {
		e.clients.MarkDisassociated(frame.DstMAC, now)
	}
	if frame.SrcMAC != nil && !isBroadcast(frame.SrcMAC) {
		e.clients.MarkDisassociated(frame.SrcMAC, now)
	}
}

// processDataFrame updates client tracking from data frames.
func (e *Engine) processDataFrame(frame *parser.ParsedFrame) {
	// Determine the client MAC based on ToDS/FromDS flags:
	// ToDS=1 FromDS=0: Addr2 = client (SrcMAC), Addr1 = BSSID
	// ToDS=0 FromDS=1: Addr1 = client (DstMAC), Addr2 = BSSID
	var clientMAC net.HardwareAddr
	var bssid net.HardwareAddr

	if frame.ToDS && !frame.FromDS {
		clientMAC = frame.SrcMAC
		bssid = frame.DstMAC // Address1 is BSSID in this case
	} else if !frame.ToDS && frame.FromDS {
		clientMAC = frame.DstMAC
		bssid = frame.SrcMAC // Address2 is BSSID in this case
	} else {
		// ToDS=0 FromDS=0 (IBSS) or ToDS=1 FromDS=1 (WDS) — skip for now
		return
	}

	if clientMAC == nil || isBroadcast(clientMAC) {
		return
	}

	now := frame.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	if e.clients.IncrementFrame(clientMAC, now, frame.Channel, bssid) {
		return
	}

	e.clients.Update(&ClientInfo{
		MAC:        clientMAC,
		BSSID:      bssid,
		Channel:    frame.Channel,
		RSSI:       frame.RSSI,
		FirstSeen:  now,
		LastSeen:   now,
		FrameCount: 1,
		Associated: true, // data implies association
	})
}

// isBroadcast checks if a MAC address is a broadcast address (ff:ff:ff:ff:ff:ff).
func isBroadcast(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}

// copyIEs creates a deep copy of the information elements map.
func copyIEs(ies map[uint8][]byte) map[uint8][]byte {
	if len(ies) == 0 {
		return nil
	}
	result := make(map[uint8][]byte, len(ies))
	for k, v := range ies {
		cp := make([]byte, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}
