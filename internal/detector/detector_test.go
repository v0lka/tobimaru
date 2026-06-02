package detector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

// countingRule returns one event per frame with a configurable type and severity.
type countingRule struct {
	name      string
	eventType string
	severity  Severity
	initErr   error
	callCount int
	mu        sync.Mutex
}

func (r *countingRule) Name() string { return r.name }

func (r *countingRule) Init(_ config.DetectionConfig) error { return r.initErr }

func (r *countingRule) Process(frame *parser.ParsedFrame) []*SecurityEvent {
	r.mu.Lock()
	r.callCount++
	r.mu.Unlock()

	if r.eventType == "" {
		return nil
	}
	return []*SecurityEvent{
		{
			Timestamp: frame.Timestamp,
			EventType: r.eventType,
			Severity:  r.severity,
			SrcMAC:    frame.SrcMAC,
			DstMAC:    frame.DstMAC,
			BSSID:     frame.BSSID,
			Channel:   frame.Channel,
			RSSI:      frame.RSSI,
			Metadata:  make(map[string]any),
		},
	}
}

func (r *countingRule) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.callCount
}

// panickingRule panics on Process to test recovery.
type panickingRule struct {
	name string
}

func (r *panickingRule) Name() string                                   { return r.name }
func (r *panickingRule) Init(_ config.DetectionConfig) error            { return nil }
func (r *panickingRule) Process(_ *parser.ParsedFrame) []*SecurityEvent { panic("intentional panic") }

// makeFrame creates a minimal ParsedFrame for testing.
func makeFrame(srcMAC, dstMAC, bssid string) *parser.ParsedFrame {
	src, _ := net.ParseMAC(srcMAC)
	dst, _ := net.ParseMAC(dstMAC)
	bss, _ := net.ParseMAC(bssid)
	return &parser.ParsedFrame{
		FrameType: parser.FrameTypeDeauth,
		Timestamp: time.Now(),
		SrcMAC:    src,
		DstMAC:    dst,
		BSSID:     bss,
		Channel:   6,
		RSSI:      -45,
	}
}

// drainAlerts reads all alerts from the channel until it closes.
func drainAlerts(ch <-chan *SecurityEvent) []*SecurityEvent {
	var alerts []*SecurityEvent
	for a := range ch {
		alerts = append(alerts, a)
	}
	return alerts
}

func TestEngineDispatch(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})

	rule := &countingRule{name: "test_rule", eventType: "test", severity: SeverityWarning}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	// Send 5 frames, each with a different SrcMAC to avoid dedup.
	for i := range 5 {
		src := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(0x55 + i)}
		frames <- makeFrame(src.String(), "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	}
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(alerts))
	}
	if rule.Calls() != 5 {
		t.Errorf("expected 5 calls, got %d", rule.Calls())
	}
}

func TestEngineMultipleRules(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})

	rule1 := &countingRule{name: "rule_a", eventType: "type_a", severity: SeverityInfo}
	rule2 := &countingRule{name: "rule_b", eventType: "type_b", severity: SeverityWarning}

	if err := engine.Register(rule1); err != nil {
		t.Fatalf("Register rule1 failed: %v", err)
	}
	if err := engine.Register(rule2); err != nil {
		t.Fatalf("Register rule2 failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	frames <- makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts (one per rule), got %d", len(alerts))
	}
	if rule1.Calls() != 1 {
		t.Errorf("rule1 expected 1 call, got %d", rule1.Calls())
	}
	if rule2.Calls() != 1 {
		t.Errorf("rule2 expected 1 call, got %d", rule2.Calls())
	}

	// Verify both types are present.
	types := make(map[string]int)
	for _, a := range alerts {
		types[a.EventType]++
	}
	if types["type_a"] != 1 || types["type_b"] != 1 {
		t.Errorf("unexpected alert types: %v", types)
	}
}

func TestEngineDuplicateRule(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})
	rule1 := &countingRule{name: "my_rule"}
	rule2 := &countingRule{name: "my_rule"}

	if err := engine.Register(rule1); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	if err := engine.Register(rule2); err == nil {
		t.Error("expected error for duplicate rule name, got nil")
	}
}

func TestEngineRuleInitError(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})
	rule := &countingRule{name: "bad_rule", initErr: errors.New("config missing")}

	if err := engine.Register(rule); err == nil {
		t.Error("expected error for rule init failure, got nil")
	}
}

func TestEngineNoRules(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts with no rules, got %d", len(alerts))
	}
}

func TestEngineDedupSameEvent(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     1 * time.Second,
	})

	rule := &countingRule{name: "r", eventType: "deauth_flood", severity: SeverityCritical}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	// Send two frames with the same MACs.
	f := makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	frames <- f
	frames <- f
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert after dedup, got %d", len(alerts))
	}
}

func TestEngineDedupDifferentType(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     1 * time.Second,
	})

	rule1 := &countingRule{name: "deauth", eventType: "deauth_flood", severity: SeverityCritical}
	rule2 := &countingRule{name: "disassoc", eventType: "disassoc_flood", severity: SeverityCritical}
	if err := engine.Register(rule1); err != nil {
		t.Fatalf("Register rule1 failed: %v", err)
	}
	if err := engine.Register(rule2); err != nil {
		t.Fatalf("Register rule2 failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	frames <- makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts (different types not deduplicated), got %d", len(alerts))
	}
}

func TestEngineDedupDifferentMAC(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     1 * time.Second,
	})

	rule := &countingRule{name: "r", eventType: "deauth_flood", severity: SeverityCritical}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	frames <- makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	frames <- makeFrame("00:11:22:33:44:66", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff") // different SrcMAC
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts (different MACs not deduplicated), got %d", len(alerts))
	}
}

func TestEngineDedupWindowExpiry(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     50 * time.Millisecond,
	})

	rule := &countingRule{name: "r", eventType: "deauth_flood", severity: SeverityCritical}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	f := makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")

	// First frame — should produce alert.
	frames <- f

	// Read the first alert.
	var first *SecurityEvent
	select {
	case first = <-engine.Alerts():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first alert")
	}
	if first == nil {
		t.Fatal("expected first alert, got nil")
	}

	// Wait for dedup window to expire.
	time.Sleep(100 * time.Millisecond)

	// Second frame — same event but window expired, should produce another alert.
	frames <- f
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert after window expiry, got %d", len(alerts))
	}
}

func TestEngineDedupSweep(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     100 * time.Millisecond,
	})

	rule := &countingRule{name: "r", eventType: "test", severity: SeverityInfo}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	f := makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	frames <- f
	close(frames)

	drainAlerts(engine.Alerts())

	// Smoke test: sweep should not panic with a freshly populated map.
	// Entry may or may not still be present depending on sweep timing
	// (it's at most 100ms old; cutoff is 200ms). Either state is valid.
	engine.mu.Lock()
	entries := len(engine.dedup)
	engine.mu.Unlock()
	t.Logf("dedup map size after drain: %d", entries)
}

func TestEngineShutdownByContext(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})

	ctx, cancel := context.WithCancel(context.Background())
	frames := make(chan *parser.ParsedFrame, 10)

	engine.Run(ctx, frames)

	// Cancel context to trigger shutdown.
	cancel()

	// Alerts channel should close.
	select {
	case _, ok := <-engine.Alerts():
		if ok {
			t.Error("expected closed channel, got value")
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for channel close")
	}
}

func TestEngineShutdownByFramesClose(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})

	ctx := context.Background()
	frames := make(chan *parser.ParsedFrame, 10)

	engine.Run(ctx, frames)

	// Close frames channel to trigger shutdown.
	close(frames)

	// Alerts channel should close.
	select {
	case _, ok := <-engine.Alerts():
		if ok {
			t.Error("expected closed channel, got value")
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for channel close")
	}
}

func TestEngineAlertsDrained(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})

	rule := &countingRule{name: "r", eventType: "test", severity: SeverityInfo}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	for range 10 {
		frames <- makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	}
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 1 { // deduplicated to 1
		t.Errorf("expected 1 deduplicated alert, got %d", len(alerts))
	}

	// Channel should be closed.
	select {
	case _, ok := <-engine.Alerts():
		if ok {
			t.Error("expected closed channel after drain")
		}
	default:
		t.Error("channel should be closed and return zero value immediately")
	}
}

func TestEngineBackpressure(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 2,
		DedupWindow:     30 * time.Second,
	})

	// Rule generates unique events to bypass dedup.
	rule := &countingRule{name: "r", eventType: "test", severity: SeverityInfo}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	// Send frames with unique MACs to produce unique events, filling the buffer.
	for i := range 10 {
		src := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, byte(0x55 + i)}
		dst := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		bss := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		frames <- &parser.ParsedFrame{
			FrameType: parser.FrameTypeDeauth,
			Timestamp: time.Now(),
			SrcMAC:    src,
			DstMAC:    dst,
			BSSID:     bss,
			Channel:   6,
			RSSI:      -45,
		}
	}
	close(frames)

	drainAlerts(engine.Alerts())
	// Should not block or panic even with buffer overflow.
}

func TestEnginePanicRecovery(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})

	panicking := &panickingRule{name: "panicker"}
	safeRule := &countingRule{name: "safe", eventType: "safe", severity: SeverityWarning}

	if err := engine.Register(panicking); err != nil {
		t.Fatalf("Register panicking failed: %v", err)
	}
	if err := engine.Register(safeRule); err != nil {
		t.Fatalf("Register safeRule failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	frames <- makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
	close(frames)

	// The safe rule should still produce its alert.
	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert from safe rule, got %d", len(alerts))
	}
	if safeRule.Calls() != 1 {
		t.Errorf("safe rule expected 1 call, got %d", safeRule.Calls())
	}
}

func TestEngineNilFrame(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})

	rule := &countingRule{name: "r", eventType: "test", severity: SeverityInfo}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	frames <- nil
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for nil frame, got %d", len(alerts))
	}
	if rule.Calls() != 0 {
		t.Errorf("expected 0 calls for nil frame, got %d", rule.Calls())
	}
}

func TestEngineConcurrentRunRace(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 128,
		DedupWindow:     30 * time.Second,
	})

	letters := []string{"a", "b", "c", "d"}
	rules := make([]*countingRule, 0, len(letters))
	for _, l := range letters {
		r := &countingRule{name: "rule_" + l, eventType: "type_" + l, severity: SeverityInfo}
		if err := engine.Register(r); err != nil {
			t.Fatalf("Register %s failed: %v", r.Name(), err)
		}
		rules = append(rules, r)
	}

	frames := make(chan *parser.ParsedFrame, 100)
	engine.Run(t.Context(), frames)

	// Send frames concurrently.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 25 {
				frames <- makeFrame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff")
			}
		})
	}
	wg.Wait()
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	// All 100 frames should be processed by 4 rules = 400 events, but dedup reduces to 4 (one per rule).
	if len(alerts) != 4 {
		t.Errorf("expected 4 deduplicated alerts (1 per rule), got %d", len(alerts))
	}

	for _, r := range rules {
		if r.Calls() != 100 {
			t.Errorf("rule %s expected 100 calls, got %d", r.Name(), r.Calls())
		}
	}
}

func TestNewEngineDefaultConfig(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{})
	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	if engine.dedupWindow <= 0 {
		t.Error("dedupWindow should have default positive value")
	}
	if cap(engine.alerts) <= 0 {
		t.Error("alerts channel should have positive buffer size")
	}
}

func TestDedupKey(t *testing.T) {
	ev := &SecurityEvent{
		EventType: "deauth_flood",
		SrcMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		BSSID:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	key := dedupKey(ev)

	ev2 := &SecurityEvent{
		EventType: "deauth_flood",
		SrcMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		BSSID:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	key2 := dedupKey(ev2)
	if key != key2 {
		t.Errorf("same events should have same dedup key: %q vs %q", key, key2)
	}

	ev3 := &SecurityEvent{
		EventType: "disassoc_flood",
		SrcMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		BSSID:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	key3 := dedupKey(ev3)
	if key == key3 {
		t.Error("different event types should have different keys")
	}
}

func TestEngineZeroAlertBufferSize(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 0,
		DedupWindow:     30 * time.Second,
	})
	if cap(engine.alerts) != config.DefaultAlertBufferSize {
		t.Errorf("expected default buffer size %d, got %d", config.DefaultAlertBufferSize, cap(engine.alerts))
	}
}

func TestEngineZeroDedupWindow(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     0,
	})
	if engine.dedupWindow != config.DefaultDedupWindow {
		t.Errorf("expected default dedup window %v, got %v", config.DefaultDedupWindow, engine.dedupWindow)
	}
}

func TestSweepDedupRemovesStaleEntries(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		AlertBufferSize: 64,
		DedupWindow:     50 * time.Millisecond,
	})

	// Insert stale entries (well past 2x dedup window).
	engine.mu.Lock()
	staleTime := time.Now().Add(-500 * time.Millisecond)
	engine.dedup["stale1"] = staleTime
	engine.dedup["stale2"] = staleTime
	engine.dedup["fresh"] = time.Now()
	engine.mu.Unlock()

	engine.sweepDedup()

	engine.mu.Lock()
	defer engine.mu.Unlock()

	if _, exists := engine.dedup["stale1"]; exists {
		t.Error("stale1 should have been swept")
	}
	if _, exists := engine.dedup["stale2"]; exists {
		t.Error("stale2 should have been swept")
	}
	if _, exists := engine.dedup["fresh"]; !exists {
		t.Error("fresh entry should remain")
	}
}

func TestSweepDedupOverflowEviction(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		AlertBufferSize: 64,
		DedupWindow:     1 * time.Hour, // long window so nothing is stale
	})

	// Insert more than maxDedupEntries entries.
	engine.mu.Lock()
	for i := range maxDedupEntries + 100 {
		key := fmt.Sprintf("key_%d", i)
		engine.dedup[key] = time.Now()
	}
	engine.mu.Unlock()

	engine.sweepDedup()

	engine.mu.Lock()
	remaining := len(engine.dedup)
	engine.mu.Unlock()

	// After sweep, oldest half should be evicted.
	if remaining > maxDedupEntries {
		t.Errorf("expected at most %d entries after sweep, got %d", maxDedupEntries, remaining)
	}
}

func TestEmitNilEvent(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})

	// emit(nil) should be a no-op.
	engine.emit(nil)

	select {
	case <-engine.alerts:
		t.Error("no alert should be emitted for nil event")
	default:
		// expected
	}
}

func TestEngineRegisterAfterRun(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})

	frames := make(chan *parser.ParsedFrame, 1)
	engine.Run(t.Context(), frames)

	rule := &countingRule{name: "late", eventType: "x", severity: SeverityInfo}
	err := engine.Register(rule)
	if err == nil {
		t.Fatal("expected error when registering after Run, got nil")
	}
	if !errors.Is(err, ErrEngineStarted) {
		t.Errorf("expected ErrEngineStarted, got %v", err)
	}

	close(frames)
	drainAlerts(engine.Alerts())
}

func TestEngineRunIdempotent(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})

	frames := make(chan *parser.ParsedFrame, 1)
	engine.Run(t.Context(), frames)
	// Second call should be a safe no-op (does not panic, does not start
	// another goroutine, does not double-close alerts).
	engine.Run(t.Context(), frames)

	close(frames)
	drainAlerts(engine.Alerts())
}

func BenchmarkDedupKey(b *testing.B) {
	ev := &SecurityEvent{
		EventType: "deauth_flood",
		SrcMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		BSSID:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = dedupKey(ev)
	}
}
