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
		t.Errorf("got %d alerts, want 5", len(alerts))
	}
	if rule.Calls() != 5 {
		t.Errorf("got %d calls, want 5", rule.Calls())
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
		t.Errorf("got %d alerts, want 2 (one per rule)", len(alerts))
	}
	if rule1.Calls() != 1 {
		t.Errorf("rule1: got %d calls, want 1", rule1.Calls())
	}
	if rule2.Calls() != 1 {
		t.Errorf("rule2: got %d calls, want 1", rule2.Calls())
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
		t.Error("got nil, want error for duplicate rule name")
	}
}

func TestEngineRuleInitError(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})
	rule := &countingRule{name: "bad_rule", initErr: errors.New("config missing")}

	if err := engine.Register(rule); err == nil {
		t.Error("got nil, want error for rule init failure")
	}
}

func TestEngineNoRules(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})

	frames := make(chan *parser.ParsedFrame, 10)
	engine.Run(t.Context(), frames)

	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 0 {
		t.Errorf("got %d alerts, want 0 (no rules)", len(alerts))
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
		t.Errorf("got %d alerts, want 1 (after dedup)", len(alerts))
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
		t.Errorf("got %d alerts, want 2 (different types not deduplicated)", len(alerts))
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
		t.Errorf("got %d alerts, want 2 (different MACs not deduplicated)", len(alerts))
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
		t.Fatal("got nil, want first alert")
	}

	// Wait for dedup window to expire.
	time.Sleep(100 * time.Millisecond)

	// Second frame — same event but window expired, should produce another alert.
	frames <- f
	close(frames)

	alerts := drainAlerts(engine.Alerts())
	if len(alerts) != 1 {
		t.Errorf("got %d alerts, want 1 (after window expiry)", len(alerts))
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
			t.Error("got value, want closed channel")
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
			t.Error("got value, want closed channel")
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
		t.Errorf("got %d alerts, want 1 (deduplicated)", len(alerts))
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
		t.Errorf("got %d alerts, want 1 (from safe rule)", len(alerts))
	}
	if safeRule.Calls() != 1 {
		t.Errorf("safe rule: got %d calls, want 1", safeRule.Calls())
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
		t.Errorf("got %d alerts, want 0 (nil frame)", len(alerts))
	}
	if rule.Calls() != 0 {
		t.Errorf("got %d calls, want 0 (nil frame)", rule.Calls())
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
		t.Errorf("got %d alerts, want 4 (deduplicated, 1 per rule)", len(alerts))
	}

	for _, r := range rules {
		if r.Calls() != 100 {
			t.Errorf("rule %s: got %d calls, want 100", r.Name(), r.Calls())
		}
	}
}

func TestNewEngineDefaultConfig(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{})
	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	if engine.DedupWindow() <= 0 {
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
		t.Errorf("got default buffer size %d, want %d", cap(engine.alerts), config.DefaultAlertBufferSize)
	}
}

func TestEngineZeroDedupWindow(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		Enabled:         true,
		AlertBufferSize: 64,
		DedupWindow:     0,
	})
	if engine.DedupWindow() != config.DefaultDedupWindow {
		t.Errorf("got default dedup window %v, want %v", engine.DedupWindow(), config.DefaultDedupWindow)
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
		t.Errorf("got %d entries after sweep, want at most %d", remaining, maxDedupEntries)
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
		t.Fatal("got nil, want error when registering after Run")
	}
	if !errors.Is(err, ErrEngineStarted) {
		t.Errorf("got %v, want ErrEngineStarted", err)
	}

	close(frames)
	drainAlerts(engine.Alerts())
}

func TestEngineSetEnabled(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})
	if engine.Enabled() {
		t.Error("expected disabled by default")
	}
	engine.SetEnabled(true)
	if !engine.Enabled() {
		t.Error("expected enabled after SetEnabled(true)")
	}
	engine.SetEnabled(false)
	if engine.Enabled() {
		t.Error("expected disabled after SetEnabled(false)")
	}
}

func TestEngineRuleCount(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{AlertBufferSize: 64})
	if n := engine.RuleCount(); n != 0 {
		t.Errorf("got %d rules, want 0", n)
	}
	rule := &countingRule{name: "r"}
	if err := engine.Register(rule); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if n := engine.RuleCount(); n != 1 {
		t.Errorf("got %d rules, want 1", n)
	}
}

func TestEngineSetDedupWindow(t *testing.T) {
	engine := NewEngine(config.DetectionConfig{
		AlertBufferSize: 64,
		DedupWindow:     30 * time.Second,
	})
	if engine.DedupWindow() != 30*time.Second {
		t.Errorf("got %v, want 30s", engine.DedupWindow())
	}
	engine.SetDedupWindow(10 * time.Second)
	if engine.DedupWindow() != 10*time.Second {
		t.Errorf("got %v, want 10s", engine.DedupWindow())
	}
	// Zero or negative should be ignored.
	engine.SetDedupWindow(0)
	if engine.DedupWindow() != 10*time.Second {
		t.Errorf("got %v, want 10s (zero should be ignored)", engine.DedupWindow())
	}
	engine.SetDedupWindow(-1 * time.Second)
	if engine.DedupWindow() != 10*time.Second {
		t.Errorf("got %v, want 10s (negative should be ignored)", engine.DedupWindow())
	}
}

func TestFrameTypeName(t *testing.T) {
	tests := []struct {
		ft   parser.FrameType
		want string
	}{
		{parser.FrameTypeAssocReq, "assoc_req"},
		{parser.FrameTypeReassocReq, "reassoc_req"},
		{parser.FrameTypeAuth, frameTypeAuth},
		{parser.FrameTypeProbeRequest, frameTypeProbeRequest},
		{parser.FrameTypeDeauth, "Deauthentication"},
		{parser.FrameTypeBeacon, "Beacon"},
		{parser.FrameTypeUnknown, "Unknown"},
	}
	for _, tc := range tests {
		got := frameTypeName(tc.ft)
		if got != tc.want {
			t.Errorf("frameTypeName(%v) = %q, want %q", tc.ft, got, tc.want)
		}
	}
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

func TestFloodRuleCleanupStale(t *testing.T) {
	r := newFloodRule("test", parser.FrameTypeDeauth, SeverityCritical, 10, time.Second)

	// Populate tracker with a mix of stale and fresh entries.
	now := time.Now()
	stale := now.Add(-time.Hour) // well beyond maxAge = window * 5 = 5s

	r.tracker["fresh"] = &floodTracker{lastSeen: now}
	r.tracker["stale"] = &floodTracker{lastSeen: stale}
	r.tracker["also_stale"] = &floodTracker{lastSeen: stale.Add(-time.Minute)}

	r.cleanupStale(now)

	if _, ok := r.tracker["fresh"]; !ok {
		t.Error("fresh entry should remain")
	}
	if _, ok := r.tracker["stale"]; ok {
		t.Error("stale entry should be removed")
	}
	if _, ok := r.tracker["also_stale"]; ok {
		t.Error("also_stale entry should be removed")
	}
	if len(r.tracker) != 1 {
		t.Errorf("expected 1 remaining entry, got %d", len(r.tracker))
	}
}
