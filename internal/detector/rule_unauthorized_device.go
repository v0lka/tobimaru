package detector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

type UnauthorizedDeviceRule struct {
	enabled      bool
	alertOnProbe bool
	cooldown     time.Duration

	protectedBSSIDs map[string]struct{}
	protectedSSIDs  map[string]struct{}
	whitelist       map[string]struct{}

	mu             sync.Mutex
	lastAlertByMAC map[string]time.Time
	callCount      uint64
}

func (r *UnauthorizedDeviceRule) Name() string {
	return "unauthorized_device"
}

func (r *UnauthorizedDeviceRule) Init(cfg config.DetectionConfig) error {
	r.enabled = cfg.UnauthorizedDevice.Enabled
	r.alertOnProbe = cfg.UnauthorizedDevice.AlertOnProbe
	r.cooldown = cfg.UnauthorizedDevice.Cooldown

	r.protectedBSSIDs = make(map[string]struct{}, len(cfg.UnauthorizedDevice.ProtectedBSSIDs))
	r.protectedSSIDs = make(map[string]struct{}, len(cfg.UnauthorizedDevice.ProtectedSSIDs))
	r.whitelist = make(map[string]struct{}, len(cfg.UnauthorizedDevice.Whitelist))
	r.lastAlertByMAC = make(map[string]time.Time)

	for _, value := range cfg.UnauthorizedDevice.ProtectedBSSIDs {
		mac, err := normalizeMAC(value)
		if err != nil {
			return fmt.Errorf("invalid protected BSSID %q: %w", value, err)
		}

		r.protectedBSSIDs[mac] = struct{}{}
	}

	for _, ssid := range cfg.UnauthorizedDevice.ProtectedSSIDs {
		if ssid == "" {
			return invalidRuleConfig(r.Name(), "protected_ssids must not contain empty SSID")
		}

		r.protectedSSIDs[ssid] = struct{}{}
	}

	for _, value := range cfg.UnauthorizedDevice.Whitelist {
		mac, err := normalizeMAC(value)
		if err != nil {
			return fmt.Errorf("invalid whitelist MAC %q: %w", value, err)
		}

		r.whitelist[mac] = struct{}{}
	}

	if r.enabled && len(r.protectedBSSIDs) == 0 && len(r.protectedSSIDs) == 0 {
		return invalidRuleConfig(r.Name(), "requires at least one protected_bssid or protected_ssid")
	}

	if r.enabled && r.alertOnProbe && len(r.protectedSSIDs) == 0 {
		return invalidRuleConfig(r.Name(), "alert_on_probe requires at least one protected_ssid")
	}
	if r.enabled && r.cooldown <= 0 {
		return invalidRuleConfig(r.Name(), "cooldown must be > 0")
	}

	return nil
}

func (r *UnauthorizedDeviceRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	if !r.enabled {
		return nil
	}

	if !r.isRelevantFrameType(frame.FrameType) {
		return nil
	}

	r.trackCall(frame.Timestamp)

	if frame.FrameType == parser.FrameTypeProbeRequest {
		return r.processProbeRequest(frame)
	}

	return r.processProtectedAPAccess(frame)
}

func (r *UnauthorizedDeviceRule) trackCall(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.callCount++
	if r.callCount%10000 == 0 {
		r.cleanupStale(now)
	}
}

func (r *UnauthorizedDeviceRule) cleanupStale(now time.Time) {
	for mac, lastAlert := range r.lastAlertByMAC {
		if now.Sub(lastAlert) > r.cooldown {
			delete(r.lastAlertByMAC, mac)
		}
	}
}

func (r *UnauthorizedDeviceRule) isRelevantFrameType(frameType parser.FrameType) bool {
	switch frameType {
	case parser.FrameTypeAssocReq,
		parser.FrameTypeReassocReq,
		parser.FrameTypeAuth:
		return true
	case parser.FrameTypeProbeRequest:
		return r.alertOnProbe
	default:
		return false
	}
}

func protectedAPKey(frame *parser.ParsedFrame) string {
	if len(frame.BSSID) > 0 {
		return frame.BSSID.String()
	}

	if len(frame.DstMAC) > 0 {
		return frame.DstMAC.String()
	}

	return ""
}

func (r *UnauthorizedDeviceRule) processProtectedAPAccess(frame *parser.ParsedFrame) []*SecurityEvent {
	protectedAP := protectedAPKey(frame)
	if protectedAP == "" {
		return nil
	}

	if _, ok := r.protectedBSSIDs[protectedAP]; !ok {
		return nil
	}

	return r.emitUnauthorizedDeviceEvent(frame, protectedAP)
}

func (r *UnauthorizedDeviceRule) processProbeRequest(frame *parser.ParsedFrame) []*SecurityEvent {
	if !r.alertOnProbe {
		return nil
	}

	if frame.SSID == "" {
		return nil
	}

	if _, ok := r.protectedSSIDs[frame.SSID]; !ok {
		return nil
	}

	return r.emitUnauthorizedDeviceEvent(frame, frame.SSID)
}

func (r *UnauthorizedDeviceRule) emitUnauthorizedDeviceEvent(
	frame *parser.ParsedFrame,
	protectedTarget string,
) []*SecurityEvent {
	srcMAC := frame.SrcMAC.String()
	now := frame.Timestamp

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.whitelist[srcMAC]; ok {
		return nil
	}

	if lastAlert, ok := r.lastAlertByMAC[srcMAC]; ok && now.Sub(lastAlert) < r.cooldown {
		return nil
	}

	r.lastAlertByMAC[srcMAC] = now

	ev := NewEvent(now, r.Name(), SeverityWarning)
	ev.SrcMAC = frame.SrcMAC
	ev.DstMAC = frame.DstMAC
	ev.BSSID = eventBSSID(frame)
	ev.SSID = frame.SSID
	ev.Channel = frame.Channel
	ev.RSSI = frame.RSSI
	ev.FrameCount = 1
	ev.Description = fmt.Sprintf(
		"Unauthorized device detected: %s attempted to access protected target %s",
		frame.SrcMAC,
		protectedTarget,
	)

	ev.Metadata["frame_type"] = frameTypeName(frame.FrameType)
	ev.Metadata["protected_target"] = protectedTarget
	ev.Metadata["cooldown"] = r.cooldown.String()

	return []*SecurityEvent{ev}
}

func eventBSSID(frame *parser.ParsedFrame) net.HardwareAddr {
	if len(frame.BSSID) > 0 {
		return frame.BSSID
	}

	return frame.DstMAC
}
