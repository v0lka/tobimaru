// Package main is the entry point for the Tobimaru WiFi Watchdog daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/vkochetkov/tobimaru/internal/capture"
	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/logging"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/shutdown"
	"github.com/vkochetkov/tobimaru/internal/version"
)

func main() {
	flagConfig := flag.String("config", "configs/tobimaru.yaml", "path to configuration file")
	flagVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *flagVersion {
		fmt.Println(version.String())
		return
	}

	cfg, err := config.Load(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := logging.New(cfg.Log)
	slog.SetDefault(logger)

	slog.Info("Tobimaru WiFi Watchdog starting",
		"version", version.Version,
		"commit", version.Commit,
		"date", version.Date,
	)

	// Create capture pipeline.
	pipeline, err := capture.NewPipeline(cfg)
	if err != nil {
		slog.Error("Failed to create capture pipeline", "error", err)
		os.Exit(1)
	}

	// Start the pipeline with signal context.
	sm := shutdown.NewManager()
	signalCtx := sm.WaitForSignal(context.Background())

	if err := pipeline.Start(signalCtx); err != nil {
		slog.Error("Failed to start capture pipeline", "error", err)
		os.Exit(1)
	}

	// Register shutdown hooks.
	sm.Register("capture_stop", func() error {
		pipeline.Stop()
		return nil
	})

	// Wire detection engine.
	engine := detector.NewEngine(cfg.Detection)
	slog.Info("detection engine created",
		"enabled", cfg.Detection.Enabled,
		"dedup_window", cfg.Detection.DedupWindow,
	)

	// Register rules (individual attack rules come in tasks 2.3-2.7).
	// engine.Register(myRule)

	if cfg.Detection.Enabled {
		engine.Run(signalCtx, pipeline.Frames())
		go consumeAlerts(signalCtx, engine.Alerts())
		sm.Register("detector_stop", func() error { return nil })
	} else {
		// Detection disabled — continue with simple frame consumer for dev/debug.
		go consumeFrames(signalCtx, pipeline.Frames())
	}

	// Wait for shutdown signal.
	<-signalCtx.Done()

	slog.Info("received shutdown signal")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	if err := sm.Shutdown(shutdownCtx); err != nil {
		cancel()
		slog.Error("Shutdown completed with errors", "error", err)
		os.Exit(1)
	}
	cancel()

	slog.Info("Shutdown complete")
}

// consumeFrames receives parsed frames from the capture pipeline and processes
// them. In the current phase, it logs summary information about captured frames.
// This is used when detection is disabled for development and debugging.
func consumeFrames(ctx context.Context, frames <-chan *parser.ParsedFrame) {
	var count uint64
	var lastReport time.Time

	for {
		select {
		case <-ctx.Done():
			slog.Info("frame consumer stopped", "total_frames", count)
			return
		case frame, ok := <-frames:
			if !ok {
				return
			}
			count++
			if time.Since(lastReport) >= 5*time.Second {
				slog.Debug("capture stats",
					"frames_received", count,
					"current_type", frame.FrameType.String(),
					"current_channel", frame.Channel,
				)
				lastReport = time.Now()
			}
		}
	}
}

// consumeAlerts receives security events from the detection engine and logs
// them at appropriate levels based on severity.
func consumeAlerts(ctx context.Context, alerts <-chan *detector.SecurityEvent) {
	var count uint64

	for {
		select {
		case <-ctx.Done():
			slog.Info("alert consumer stopped", "total_alerts", count)
			return
		case event, ok := <-alerts:
			if !ok {
				return
			}
			count++

			args := []any{
				"type", event.EventType,
				"severity", event.Severity.String(),
				"channel", event.Channel,
				"src_mac", event.SrcMAC,
				"bssid", event.BSSID,
			}
			if event.SSID != "" {
				args = append(args, "ssid", event.SSID)
			}
			if event.Description != "" {
				args = append(args, "description", event.Description)
			}

			switch event.Severity {
			case detector.SeverityCritical:
				slog.Error("security alert", args...)
			case detector.SeverityWarning:
				slog.Warn("security alert", args...)
			default:
				slog.Info("security alert", args...)
			}
		}
	}
}
