package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

type BeaconFloodRule struct {
	threshold      int
	window         time.Duration
	learningPeriod time.Duration

	mu          sync.Mutex
	startedAt   time.Time
	knownBSSIDs map[string]time.Time
	channels    map[int]*beaconChannelState
	callCount   uint64
}

type beaconChannelState struct {
	windowStart time.Time
	lastSeen    time.Time
	beaconCount int
	newBSSIDs   map[string]time.Time
	sampleSSIDs map[string]struct{}
	rssiCounts  map[int]int
}

func (r *BeaconFloodRule) Name() string {
	return "beacon_flood"
}

func (r *BeaconFloodRule) Init(cfg config.DetectionConfig) error {
	r.threshold = cfg.BeaconFlood.Threshold
	r.window = cfg.BeaconFlood.Window
	r.learningPeriod = cfg.BeaconFlood.LearningPeriod

	if r.threshold <= 0 {
		r.threshold = config.DefaultBeaconFloodThreshold
	}
	if r.window <= 0 {
		r.window = config.DefaultBeaconFloodWindow
	}
	if r.learningPeriod < 0 {
		return invalidRuleConfig(r.Name(), "learning_period must be >= 0")
	}
	if r.learningPeriod == 0 {
		r.learningPeriod = config.DefaultBeaconFloodLearningPeriod
	}

	r.knownBSSIDs = make(map[string]time.Time)
	r.channels = make(map[int]*beaconChannelState)

	return nil
}

func (r *BeaconFloodRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	if frame.FrameType != parser.FrameTypeBeacon {
		return nil
	}
	if len(frame.BSSID) == 0 {
		return nil
	}

	now := frame.Timestamp
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

	if now.Sub(r.startedAt) < r.learningPeriod {
		r.knownBSSIDs[bssid] = now
		return nil
	}

	if _, known := r.knownBSSIDs[bssid]; known {
		r.knownBSSIDs[bssid] = now
		return nil
	}

	st := r.channelState(frame.Channel, now)

	if now.Sub(st.windowStart) > r.window {
		r.promoteWindowToKnown(st)
		st.reset(now)
	}

	st.lastSeen = now
	st.beaconCount++
	st.newBSSIDs[bssid] = now

	if frame.SSID != "" && len(st.sampleSSIDs) < 5 {
		st.sampleSSIDs[frame.SSID] = struct{}{}
	}

	st.rssiCounts[frame.RSSI]++

	if len(st.newBSSIDs) < r.threshold {
		return nil
	}

	ev := NewEvent(now, r.Name(), SeverityWarning)
	ev.Channel = frame.Channel
	ev.RSSI = frame.RSSI
	ev.FrameCount = st.beaconCount
	ev.Duration = now.Sub(st.windowStart)
	ev.Description = fmt.Sprintf(
		"Beacon flood detected: %d new unique BSSIDs in %v on channel %d",
		len(st.newBSSIDs),
		ev.Duration.Round(time.Second),
		frame.Channel,
	)

	ev.Metadata["new_bssid_count"] = len(st.newBSSIDs)
	ev.Metadata["threshold"] = r.threshold
	ev.Metadata["window"] = r.window.String()
	ev.Metadata["learning_period"] = r.learningPeriod.String()
	ev.Metadata["sample_ssids"] = sampleSSIDList(st.sampleSSIDs)

	if commonRSSI, ok := dominantRSSI(st.rssiCounts, st.beaconCount); ok {
		ev.Metadata["common_rssi"] = commonRSSI
	}

	r.promoteWindowToKnown(st)
	st.reset(now)

	return []*SecurityEvent{ev}
}

func (r *BeaconFloodRule) channelState(channel int, now time.Time) *beaconChannelState {
	st, ok := r.channels[channel]
	if ok {
		return st
	}

	st = &beaconChannelState{}
	st.reset(now)
	r.channels[channel] = st

	return st
}

func (st *beaconChannelState) reset(now time.Time) {
	st.windowStart = now
	st.lastSeen = now
	st.beaconCount = 0
	st.newBSSIDs = make(map[string]time.Time)
	st.sampleSSIDs = make(map[string]struct{})
	st.rssiCounts = make(map[int]int)
}

func (r *BeaconFloodRule) promoteWindowToKnown(st *beaconChannelState) {
	for bssid, seenAt := range st.newBSSIDs {
		r.knownBSSIDs[bssid] = seenAt
	}
}

func (r *BeaconFloodRule) cleanupStale(now time.Time) {
	maxAge := r.learningPeriod + 10*r.window

	for bssid, lastSeen := range r.knownBSSIDs {
		if now.Sub(lastSeen) > maxAge {
			delete(r.knownBSSIDs, bssid)
		}
	}

	for channel, st := range r.channels {
		if now.Sub(st.lastSeen) > maxAge {
			delete(r.channels, channel)
		}
	}
}

func sampleSSIDList(ssids map[string]struct{}) []string {
	result := make([]string, 0, len(ssids))

	for ssid := range ssids {
		result = append(result, ssid)
	}

	return result
}

func dominantRSSI(rssiCounts map[int]int, total int) (int, bool) {
	if total == 0 {
		return 0, false
	}

	var commonRSSI int
	var commonCount int

	for rssi, count := range rssiCounts {
		if count > commonCount {
			commonRSSI = rssi
			commonCount = count
		}
	}

	return commonRSSI, commonCount*100 >= total*80
}
