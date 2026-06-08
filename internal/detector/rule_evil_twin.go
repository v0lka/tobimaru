package detector

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

type EvilTwinRule struct {
	scoreThreshold int
	staleTimeout   time.Duration
	learningPeriod time.Duration
	minBeacons     int

	mu        sync.Mutex
	startedAt time.Time
	apsBySSID map[string][]*evilTwinAPRecord
	alerted   map[string]time.Time
	callCount uint64
}

type evilTwinAPRecord struct {
	HardwareAddr   net.HardwareAddr
	BSSID          string
	Channel        int
	InfoElements   map[uint8][]byte
	Capability     uint16
	BeaconInterval uint16
	FirstSeen      time.Time
	LastSeen       time.Time
	RSSI           int
	BeaconCount    int
}

func (r *EvilTwinRule) Name() string {
	return "evil_twin"
}

func (r *EvilTwinRule) Init(cfg config.DetectionConfig) error {
	r.scoreThreshold = cfg.EvilTwin.ScoreThreshold
	r.staleTimeout = cfg.EvilTwin.StaleTimeout
	r.learningPeriod = cfg.EvilTwin.LearningPeriod
	r.minBeacons = cfg.EvilTwin.MinBeacons

	if r.scoreThreshold <= 0 {
		r.scoreThreshold = config.DefaultEvilTwinScoreThreshold
	}
	if r.staleTimeout <= 0 {
		r.staleTimeout = config.DefaultEvilTwinStaleTimeout
	}
	if r.learningPeriod < 0 {
		return invalidRuleConfig(r.Name(), "learning_period must be >= 0")
	}
	if r.learningPeriod == 0 {
		r.learningPeriod = config.DefaultEvilTwinLearningPeriod
	}
	if r.minBeacons <= 0 {
		r.minBeacons = config.DefaultEvilTwinMinBeacons
	}

	r.apsBySSID = make(map[string][]*evilTwinAPRecord)
	r.alerted = make(map[string]time.Time)

	return nil
}

func (r *EvilTwinRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	if frame.FrameType != parser.FrameTypeBeacon &&
		frame.FrameType != parser.FrameTypeProbeResponse {
		return nil
	}

	if frame.SSID == "" || len(frame.BSSID) == 0 {
		return nil
	}

	now := frame.Timestamp
	ssid := frame.SSID
	bssid := frame.BSSID.String()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.startedAt.IsZero() {
		r.startedAt = now
	}

	r.callCount++
	if r.callCount%10000 == 0 {
		r.cleanupStale(now)
	}

	records := r.apsBySSID[ssid]

	for _, record := range records {
		if record.BSSID == bssid {
			r.updateAPRecord(record, frame)
			return r.evaluateCandidateLocked(frame, ssid, record)
		}
	}

	candidate := newEvilTwinAPRecord(frame)
	r.apsBySSID[ssid] = append(records, candidate)

	return r.evaluateCandidateLocked(frame, ssid, candidate)
}

func (r *EvilTwinRule) evaluateCandidateLocked(
	frame *parser.ParsedFrame,
	ssid string,
	candidate *evilTwinAPRecord,
) []*SecurityEvent {
	now := frame.Timestamp

	if now.Sub(r.startedAt) < r.learningPeriod {
		return nil
	}

	if candidate.BeaconCount < r.minBeacons {
		return nil
	}

	legitimate := r.firstObservedAP(ssid, candidate.BSSID)
	if legitimate == nil || legitimate.BeaconCount < r.minBeacons {
		return nil
	}

	score, mismatches := evilTwinScore(legitimate, candidate)
	if score < r.scoreThreshold {
		return nil
	}

	alertKey := ssid + ":" + legitimate.BSSID + ":" + candidate.BSSID
	if last, ok := r.alerted[alertKey]; ok && now.Sub(last) < r.staleTimeout {
		return nil
	}

	r.alerted[alertKey] = now

	ev := NewEvent(now, r.Name(), SeverityCritical)
	ev.SrcMAC = candidate.HardwareAddr
	ev.BSSID = legitimate.HardwareAddr
	ev.SSID = ssid
	ev.Channel = candidate.Channel
	ev.RSSI = candidate.RSSI
	ev.FrameCount = candidate.BeaconCount
	ev.Duration = now.Sub(candidate.FirstSeen)
	ev.Description = fmt.Sprintf(
		"Evil Twin suspected for SSID %q: BSSID %s differs from known BSSID %s with score %d",
		ssid,
		candidate.BSSID,
		legitimate.BSSID,
		score,
	)

	ev.Metadata["legitimate_bssid"] = legitimate.BSSID
	ev.Metadata["legitimate_channel"] = legitimate.Channel
	ev.Metadata["score"] = score
	ev.Metadata["ie_mismatch"] = mismatches
	ev.Metadata["new_bssid"] = candidate.BSSID
	ev.Metadata["new_channel"] = candidate.Channel
	ev.Metadata["new_rssi"] = candidate.RSSI
	ev.Metadata["min_beacons"] = r.minBeacons

	return []*SecurityEvent{ev}
}

func newEvilTwinAPRecord(frame *parser.ParsedFrame) *evilTwinAPRecord {
	return &evilTwinAPRecord{
		HardwareAddr:   append(net.HardwareAddr(nil), frame.BSSID...),
		BSSID:          frame.BSSID.String(),
		Channel:        frame.Channel,
		InfoElements:   cloneInfoElements(frame.InfoElements),
		Capability:     frame.Capability,
		BeaconInterval: frame.BeaconInterval,
		FirstSeen:      frame.Timestamp,
		LastSeen:       frame.Timestamp,
		RSSI:           frame.RSSI,
		BeaconCount:    1,
	}
}

func (r *EvilTwinRule) updateAPRecord(record *evilTwinAPRecord, frame *parser.ParsedFrame) {
	record.LastSeen = frame.Timestamp
	record.RSSI = frame.RSSI
	record.BeaconCount++

	if frame.Channel != 0 {
		record.Channel = frame.Channel
	}
	if frame.InfoElements != nil {
		record.InfoElements = cloneInfoElements(frame.InfoElements)
	}
	if frame.Capability != 0 {
		record.Capability = frame.Capability
	}
	if frame.BeaconInterval != 0 {
		record.BeaconInterval = frame.BeaconInterval
	}
}

func (r *EvilTwinRule) firstObservedAP(ssid, excludeBSSID string) *evilTwinAPRecord {
	var first *evilTwinAPRecord

	for _, record := range r.apsBySSID[ssid] {
		if record.BSSID == excludeBSSID {
			continue
		}

		if first == nil || record.FirstSeen.Before(first.FirstSeen) {
			first = record
		}
	}

	return first
}

func evilTwinScore(known, candidate *evilTwinAPRecord) (int, []string) {
	score := 50
	mismatches := []string{"bssid"}

	if known.Channel != 0 &&
		candidate.Channel != 0 &&
		known.Channel != candidate.Channel {
		score += 30
		mismatches = append(mismatches, "channel")
	}

	if !sameIE(known.InfoElements, candidate.InfoElements, 48) {
		score += 40
		mismatches = append(mismatches, "rsn")
	}

	if !sameIE(known.InfoElements, candidate.InfoElements, 221) {
		score += 20
		mismatches = append(mismatches, "vendor")
	}

	if known.Capability != candidate.Capability {
		score += 20
		mismatches = append(mismatches, "capability")
	}

	if !sameIE(known.InfoElements, candidate.InfoElements, 45) {
		mismatches = append(mismatches, "ht_capabilities")
	}

	if !sameIE(known.InfoElements, candidate.InfoElements, 191) {
		mismatches = append(mismatches, "vht_capabilities")
	}

	if !sameIE(known.InfoElements, candidate.InfoElements, 127) {
		mismatches = append(mismatches, "extended_capabilities")
	}

	return score, mismatches
}

func sameIE(a, b map[uint8][]byte, id uint8) bool {
	ieA, okA := a[id]
	ieB, okB := b[id]

	if okA != okB {
		return false
	}

	if !okA && !okB {
		return true
	}

	return bytes.Equal(ieA, ieB)
}

func cloneInfoElements(src map[uint8][]byte) map[uint8][]byte {
	if src == nil {
		return nil
	}

	dst := make(map[uint8][]byte, len(src))

	for id, value := range src {
		dst[id] = append([]byte(nil), value...)
	}

	return dst
}

func (r *EvilTwinRule) cleanupStale(now time.Time) {
	for ssid, records := range r.apsBySSID {
		active := records[:0]

		for _, record := range records {
			if now.Sub(record.LastSeen) <= r.staleTimeout {
				active = append(active, record)
			}
		}

		if len(active) == 0 {
			delete(r.apsBySSID, ssid)
			continue
		}

		r.apsBySSID[ssid] = active
	}

	for key, seenAt := range r.alerted {
		if now.Sub(seenAt) > r.staleTimeout {
			delete(r.alerted, key)
		}
	}
}
