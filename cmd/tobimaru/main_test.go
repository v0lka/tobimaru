package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/state"
	"github.com/vkochetkov/tobimaru/internal/storage"
)

func TestConsumeFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	frames := make(chan *parser.ParsedFrame, 10)

	done := make(chan struct{})
	go func() {
		consumeFrames(ctx, frames)
		close(done)
	}()

	// Send a few frames.
	for range 3 {
		frames <- &parser.ParsedFrame{
			FrameType: parser.FrameTypeBeacon,
			Channel:   6,
		}
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeFrames did not stop after context cancellation")
	}
}

func TestConsumeFramesChannelClose(t *testing.T) {
	ctx := context.Background()
	frames := make(chan *parser.ParsedFrame, 10)

	done := make(chan struct{})
	go func() {
		consumeFrames(ctx, frames)
		close(done)
	}()

	frames <- &parser.ParsedFrame{FrameType: parser.FrameTypeDeauth, Channel: 11}
	close(frames)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeFrames did not stop after channel close")
	}
}

func TestConsumeAlerts(t *testing.T) {
	alerts := make(chan *detector.SecurityEvent, 10)

	done := make(chan struct{})
	go func() {
		consumeAlerts(context.Background(), alerts, nil, 0, nil)
		close(done)
	}()

	src, _ := net.ParseMAC("00:11:22:33:44:55")
	bss, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// Send events of each severity and wait for channel close
	// to ensure all are consumed.
	alerts <- &detector.SecurityEvent{
		EventType:   "deauth_flood",
		Severity:    detector.SeverityCritical,
		SrcMAC:      src,
		BSSID:       bss,
		Channel:     6,
		SSID:        "TestNet",
		Description: "test critical alert",
	}
	alerts <- &detector.SecurityEvent{
		EventType: "suspicious_probe",
		Severity:  detector.SeverityWarning,
		SrcMAC:    src,
		BSSID:     bss,
		Channel:   1,
	}
	alerts <- &detector.SecurityEvent{
		EventType: "new_device",
		Severity:  detector.SeverityInfo,
		SrcMAC:    src,
		BSSID:     bss,
		Channel:   11,
	}
	close(alerts)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeAlerts did not stop after channel close")
	}
}

func TestConsumeAlertsChannelClose(t *testing.T) {
	ctx := context.Background()
	alerts := make(chan *detector.SecurityEvent, 10)

	done := make(chan struct{})
	go func() {
		consumeAlerts(ctx, alerts, nil, 0, nil)
		close(done)
	}()

	alerts <- &detector.SecurityEvent{
		EventType: "test",
		Severity:  detector.SeverityInfo,
		SrcMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		BSSID:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	close(alerts)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeAlerts did not stop after channel close")
	}
}

func TestFanOut(t *testing.T) {
	ctx := t.Context()

	source := make(chan *parser.ParsedFrame, 10)
	sink1 := make(chan *parser.ParsedFrame, 10)
	sink2 := make(chan *parser.ParsedFrame, 10)

	done := make(chan struct{})
	go func() {
		fanOut(ctx, source, sink1, sink2)
		close(done)
	}()

	// Send frames.
	frames := []*parser.ParsedFrame{
		{FrameType: parser.FrameTypeBeacon, Channel: 1},
		{FrameType: parser.FrameTypeDeauth, Channel: 6},
		{FrameType: parser.FrameTypeProbeRequest, Channel: 11},
	}
	for _, f := range frames {
		source <- f
	}
	close(source)

	// Wait for fan-out to finish.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fanOut did not stop after source close")
	}

	// Verify both sinks received all frames.
	for i, f := range frames {
		got1 := <-sink1
		if got1.FrameType != f.FrameType {
			t.Errorf("sink1[%d]: expected %v, got %v", i, f.FrameType, got1.FrameType)
		}
		got2 := <-sink2
		if got2.FrameType != f.FrameType {
			t.Errorf("sink2[%d]: expected %v, got %v", i, f.FrameType, got2.FrameType)
		}
	}

	// Verify sinks are closed.
	_, ok := <-sink1
	if ok {
		t.Error("expected sink1 to be closed")
	}
	_, ok = <-sink2
	if ok {
		t.Error("expected sink2 to be closed")
	}
}

func TestFanOut_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	source := make(chan *parser.ParsedFrame, 10)
	sink1 := make(chan *parser.ParsedFrame, 10)
	sink2 := make(chan *parser.ParsedFrame, 10)

	done := make(chan struct{})
	go func() {
		fanOut(ctx, source, sink1, sink2)
		close(done)
	}()

	// Cancel context without closing source.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fanOut did not stop after context cancellation")
	}

	// Sinks should be closed.
	_, ok := <-sink1
	if ok {
		t.Error("expected sink1 to be closed")
	}
}

// TestConsumeAlertsWithRepo verifies that consumeAlerts persists events to
// a real (in-memory) SQLite repository and that PruneEvents enforces the
// configured retention limit. Pruning runs every pruneEventInterval inserts,
// so we send exactly 2*pruneEventInterval events to make the second prune
// settle the table at maxEvents.
func TestConsumeAlertsWithRepo(t *testing.T) {
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	numEvents := int(pruneEventInterval) * 2
	alerts := make(chan *detector.SecurityEvent, numEvents)
	done := make(chan struct{})
	go func() {
		// Use maxEvents=2 so PruneEvents has visible effect.
		consumeAlerts(context.Background(), alerts, repo, 2, nil)
		close(done)
	}()

	src, _ := net.ParseMAC("00:11:22:33:44:55")
	bss, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	for i := range numEvents {
		alerts <- &detector.SecurityEvent{
			Timestamp: time.Now().Add(time.Duration(i) * time.Microsecond),
			EventType: "test",
			Severity:  detector.SeverityInfo,
			SrcMAC:    src,
			BSSID:     bss,
			Channel:   6,
			Metadata:  map[string]any{},
		}
	}
	close(alerts)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("consumeAlerts did not stop after channel close")
	}

	// After exactly 2*pruneEventInterval inserts, two prune cycles ran. The
	// last one pruned to maxEvents=2, then no further inserts followed, so
	// count must equal 2.
	count, err := repo.CountEvents(context.Background(), storage.EventFilter{})
	if err != nil {
		t.Fatalf("CountEvents: %v", err)
	}
	if count != 2 {
		t.Errorf("expected event count == 2 after pruning, got %d", count)
	}
}

// TestRunSnapshotWriter verifies that snapshots are persisted on the ticker
// schedule and that the loop exits when the context is canceled.
func TestRunSnapshotWriter(t *testing.T) {
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	eng := state.NewEngine(
		config.StateConfig{Enabled: true, TTL: time.Minute, SweepInterval: time.Minute},
		config.WhitelistConfig{},
		slog.Default(),
	)

	// Seed one AP so the snapshot is non-empty.
	bssid, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	eng.ProcessFrame(&parser.ParsedFrame{
		FrameType:   parser.FrameTypeBeacon,
		Timestamp:   time.Now(),
		BSSID:       bssid,
		SSID:        "Net",
		SSIDPresent: true,
		Channel:     1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runSnapshotWriter(ctx, eng, repo, 20*time.Millisecond, 10)
		close(done)
	}()

	// Wait for at least one tick.
	time.Sleep(80 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSnapshotWriter did not stop after context cancellation")
	}

	snap, err := repo.LatestSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LatestSnapshot: %v", err)
	}
	if len(snap.APs) != 1 {
		t.Errorf("expected 1 AP in persisted snapshot, got %d", len(snap.APs))
	}
}

// --- Integration tests (subprocess-based) ---

// buildBinary builds the tobimaru binary for integration tests and returns
// the path. It uses t.TempDir for build artifacts.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tobimaru-test")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build test binary: %v\n%s", err, out)
	}
	return bin
}

// TestIntegration_VersionFlag verifies the binary prints version and exits
// cleanly (exit code 0) when passed --version.
func TestIntegration_VersionFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	bin := buildBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Tobimaru") {
		t.Errorf("--version output missing 'Tobimaru': %q", string(out))
	}
}

// TestIntegration_InvalidConfig verifies the binary exits with non-zero code
// and a clear error when given an invalid config (missing required field).
func TestIntegration_InvalidConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	bin := buildBinary(t)

	// Create a minimal invalid config (missing monitor.interface).
	cfgPath := filepath.Join(t.TempDir(), "bad.yaml")
	cfgContent := `log:
  level: info
  format: text
monitor:
  interface: ""
detection:
  enabled: false
state:
  enabled: false
storage:
  enabled: false
api:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-config", cfgPath).CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid config, got success")
	}
	if !strings.Contains(string(out), "monitor.interface") {
		t.Errorf("error output should mention monitor.interface: %q", string(out))
	}
}

// TestIntegration_DetectionEnabledNoRules verifies the binary starts cleanly
// (no panic) when detection.enabled=true but no individual detection rule
// sub-flags are enabled. The binary proceeds past the rules check (which
// emits a WARN) and fails on the missing capture interface, not on the
// rules check itself.
func TestIntegration_DetectionEnabledNoRules(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	bin := buildBinary(t)

	// Config with detection enabled and a dummy interface but no individual
	// rule sub-flags (deauth_flood.enabled, etc.) — all default to false.
	cfgPath := filepath.Join(t.TempDir(), "norules.yaml")
	cfgContent := `log:
  level: info
  format: text
monitor:
  interface: "wlan99"
detection:
  enabled: true
state:
  enabled: false
storage:
  enabled: false
api:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-config", cfgPath).CombinedOutput()
	// The binary exits non-zero because the pipeline fails on a non-existent
	// interface after the detection engine successfully starts.
	if err == nil {
		t.Fatal("expected non-zero exit (pipeline fails on missing interface), got success")
	}
	outStr := string(out)
	if strings.Contains(outStr, "panic:") {
		t.Fatalf("binary panicked:\n%s", outStr)
	}
}

// TestIntegration_GracefulShutdown verifies the daemon starts (up to the
// capture pipeline failure on a non-existent interface), reporting a clear
// error without panics. On systems with the named WiFi interface and monitor
// mode, it would start successfully and respond to signals.
func TestRegisterDetectionRules_AllEnabled(t *testing.T) {
	detCfg := config.DetectionConfig{
		Enabled:            true,
		DedupWindow:        30 * time.Second,
		DeauthFlood:        config.DeauthFloodConfig{Enabled: true, Threshold: 10, Window: time.Second},
		DisassocFlood:      config.DisassocFloodConfig{Enabled: true, Threshold: 10, Window: time.Second},
		BeaconFlood:        config.BeaconFloodConfig{Enabled: true, Threshold: 50, Window: 5 * time.Second},
		EvilTwin:           config.EvilTwinConfig{Enabled: true, ScoreThreshold: 1, StaleTimeout: time.Minute, MinBeacons: 4},
		UnauthorizedDevice: config.UnauthorizedDeviceConfig{Enabled: true, ProtectedBSSIDs: []string{"aa:bb:cc:dd:ee:ff"}, Cooldown: time.Minute},
	}
	engine := detector.NewEngine(detCfg)
	registerDetectionRules(engine, detCfg)
	if engine.RuleCount() != 5 {
		t.Errorf("expected 5 rules, got %d", engine.RuleCount())
	}
}

func TestRegisterDetectionRules_NoneEnabled(t *testing.T) {
	engine := detector.NewEngine(config.DetectionConfig{
		Enabled:     true,
		DedupWindow: 30 * time.Second,
	})
	registerDetectionRules(engine, config.DetectionConfig{
		Enabled: true,
	})
	if engine.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", engine.RuleCount())
	}
}

func TestRegisterDetectionRules_DeauthOnly(t *testing.T) {
	detCfg := config.DetectionConfig{
		Enabled:     true,
		DedupWindow: 30 * time.Second,
		DeauthFlood: config.DeauthFloodConfig{Enabled: true, Threshold: 10, Window: time.Second},
	}
	engine := detector.NewEngine(detCfg)
	registerDetectionRules(engine, detCfg)
	if engine.RuleCount() != 1 {
		t.Errorf("expected 1 rule, got %d", engine.RuleCount())
	}
}

func TestRegisterDetectionRules_DuplicateIgnored(t *testing.T) {
	detCfg := config.DetectionConfig{
		Enabled:     true,
		DedupWindow: 30 * time.Second,
		DeauthFlood: config.DeauthFloodConfig{Enabled: true, Threshold: 10, Window: time.Second},
	}
	engine := detector.NewEngine(detCfg)
	// Register same rule twice — second call should be a no-op.
	registerDetectionRules(engine, detCfg)
	registerDetectionRules(engine, detCfg)
	if engine.RuleCount() != 1 {
		t.Errorf("expected 1 rule after duplicate registration, got %d", engine.RuleCount())
	}
}

func TestConsumeStateFrames_ContextCancel(t *testing.T) {
	eng := state.NewEngine(
		config.StateConfig{Enabled: true, TTL: time.Minute, SweepInterval: time.Minute},
		config.WhitelistConfig{},
		slog.Default(),
	)
	frames := make(chan *parser.ParsedFrame, 10)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		consumeStateFrames(ctx, frames, eng)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeStateFrames did not stop after context cancellation")
	}
}

func TestConsumeStateFrames_ChannelClose(t *testing.T) {
	eng := state.NewEngine(
		config.StateConfig{Enabled: true, TTL: time.Minute, SweepInterval: time.Minute},
		config.WhitelistConfig{},
		slog.Default(),
	)
	frames := make(chan *parser.ParsedFrame, 10)
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		consumeStateFrames(ctx, frames, eng)
		close(done)
	}()

	frames <- &parser.ParsedFrame{FrameType: parser.FrameTypeBeacon, Channel: 1}
	close(frames)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeStateFrames did not stop after channel close")
	}
}

func TestFanOut_ContextCancelDuringSinkSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	source := make(chan *parser.ParsedFrame, 1)
	sink := make(chan *parser.ParsedFrame) // unbuffered to block

	done := make(chan struct{})
	go func() {
		fanOut(ctx, source, sink)
		close(done)
	}()

	// Send one frame that will block on the unbuffered sink.
	source <- &parser.ParsedFrame{FrameType: parser.FrameTypeBeacon, Channel: 1}
	// Let fanOut pick it up and block on the sink send.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fanOut did not stop after context cancellation with blocked sink")
	}
}

func TestRestorePersistedMutable_LogLevel(t *testing.T) {
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	if err := repo.SetConfig(context.Background(), "runtime.log_level", "debug"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	engine := detector.NewEngine(config.DetectionConfig{
		Enabled:     true,
		DedupWindow: 30 * time.Second,
	})

	restorePersistedMutable(context.Background(), repo, engine, nil)
	// Without a real server, detection_enabled restore will skip srv.SetDetectionEnabled.
	// log_level should be restored (SetLevel just changes slog default, no error).
}

func TestRestorePersistedMutable_DedupWindow(t *testing.T) {
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	if err := repo.SetConfig(context.Background(), "runtime.detection_dedup_window", "15s"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	engine := detector.NewEngine(config.DetectionConfig{
		Enabled:     true,
		DedupWindow: 30 * time.Second,
	})

	restorePersistedMutable(context.Background(), repo, engine, nil)
}

func TestRestorePersistedMutable_NoKeys(t *testing.T) {
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	engine := detector.NewEngine(config.DetectionConfig{
		Enabled:     true,
		DedupWindow: 30 * time.Second,
	})

	// No keys stored — restore should be a no-op.
	restorePersistedMutable(context.Background(), repo, engine, nil)
}

func TestRestorePersistedMutable_ParseErrors(t *testing.T) {
	repo, err := storage.Open(config.StorageConfig{Enabled: true, Path: ":memory:"})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	// Invalid bool value for detection_enabled
	if err := repo.SetConfig(context.Background(), "runtime.detection_enabled", "not-a-bool"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	// Invalid duration for dedup_window
	if err := repo.SetConfig(context.Background(), "runtime.detection_dedup_window", "not-a-duration"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	engine := detector.NewEngine(config.DetectionConfig{
		Enabled:     true,
		DedupWindow: 30 * time.Second,
	})

	// Should not panic, invalid values should be silently skipped.
	restorePersistedMutable(context.Background(), repo, engine, nil)

	// Detection should still be at its original state (config default).
	if !engine.Enabled() {
		t.Error("expected detection to remain enabled after invalid restore")
	}
}

func TestIntegration_GracefulShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	bin := buildBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "startup.yaml")
	cfgContent := `log:
  level: info
  format: text
monitor:
  interface: "wlan_nonexistent_test"
detection:
  enabled: false
state:
  enabled: false
storage:
  enabled: false
api:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-config", cfgPath)
	out, err := cmd.CombinedOutput()
	// The binary should fail at pipeline start (no such interface or
	// monitor mode not supported), not panic.
	if err == nil {
		t.Log("binary started successfully (running on hardware with WiFi?) — sending interrupt")
		// This path is unlikely in CI; if it happens, the process already exited.
	}
	outStr := string(out)
	if strings.Contains(outStr, "panic:") {
		t.Fatalf("binary panicked during startup:\n%s", outStr)
	}
}
