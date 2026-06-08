package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/vkochetkov/tobimaru/internal/parser"
)

type floodRule struct {
	name      string
	frameType parser.FrameType
	severity  Severity

	threshold int
	window    time.Duration

	mu        sync.Mutex
	tracker   map[string]*floodTracker
	callCount uint64
}

type floodTracker struct {
	timestamps []time.Time
	lastSeen   time.Time
}

func newFloodRule(
	name string,
	frameType parser.FrameType,
	severity Severity,
	threshold int,
	window time.Duration,
) *floodRule {
	return &floodRule{
		name:      name,
		frameType: frameType,
		severity:  severity,
		threshold: threshold,
		window:    window,
		tracker:   make(map[string]*floodTracker),
	}
}

func (r *floodRule) process(frame *parser.ParsedFrame) []*SecurityEvent {
	if frame.FrameType != r.frameType {
		return nil
	}

	now := frame.Timestamp
	key := floodKey(frame)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.callCount++
	if r.callCount%10000 == 0 {
		r.cleanupStale(now)
	}

	tr, ok := r.tracker[key]
	if !ok {
		tr = &floodTracker{}
		r.tracker[key] = tr
	}

	tr.lastSeen = now
	tr.timestamps = append(tr.timestamps, now)

	cutoff := now.Add(-r.window)
	i := 0
	for i < len(tr.timestamps) && tr.timestamps[i].Before(cutoff) {
		i++
	}
	tr.timestamps = tr.timestamps[i:]

	if len(tr.timestamps) < r.threshold {
		return nil
	}

	ev := NewEvent(now, r.name, r.severity)
	ev.SrcMAC = frame.SrcMAC
	ev.DstMAC = frame.DstMAC
	ev.BSSID = frame.BSSID
	ev.Channel = frame.Channel
	ev.RSSI = frame.RSSI
	ev.FrameCount = len(tr.timestamps)
	ev.Duration = now.Sub(tr.timestamps[0])
	ev.Description = fmt.Sprintf(
		"%s detected: %d frames in %v from %s targeting BSSID %s",
		r.name,
		ev.FrameCount,
		ev.Duration.Round(time.Second),
		frame.SrcMAC,
		frame.BSSID,
	)

	ev.Metadata["reason_code"] = frame.ReasonCode
	ev.Metadata["threshold"] = r.threshold
	ev.Metadata["window"] = r.window.String()
	ev.Metadata["tracking_key"] = key
	ev.Metadata["broadcast"] = isBroadcastMAC(frame.DstMAC)

	tr.timestamps = tr.timestamps[:0]

	return []*SecurityEvent{ev}
}

func (r *floodRule) cleanupStale(now time.Time) {
	maxAge := r.window * 5

	for key, tr := range r.tracker {
		if now.Sub(tr.lastSeen) > maxAge {
			delete(r.tracker, key)
		}
	}
}

func floodKey(frame *parser.ParsedFrame) string {
	if len(frame.BSSID) > 0 {
		return frame.SrcMAC.String() + ":" + frame.BSSID.String()
	}

	return frame.SrcMAC.String()
}
