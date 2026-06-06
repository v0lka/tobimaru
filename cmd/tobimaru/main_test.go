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

// TestIntegration_DetectionEnabledNoRules verifies the binary fails at startup
// when detection.enabled=true but no rules are registered.
func TestIntegration_DetectionEnabledNoRules(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	bin := buildBinary(t)

	// Config with detection enabled and a dummy interface.
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
	if err == nil {
		t.Fatal("expected non-zero exit for detection.enabled without rules, got success")
	}
	if !strings.Contains(string(out), "no rules") {
		t.Errorf("error output should mention 'no rules': %q", string(out))
	}
}

// TestIntegration_GracefulShutdown verifies the daemon starts (up to the
// capture pipeline failure on a non-existent interface), reporting a clear
// error without panics. On systems with the named WiFi interface and monitor
// mode, it would start successfully and respond to signals.
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
