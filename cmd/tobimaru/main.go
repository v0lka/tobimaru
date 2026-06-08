// Package main is the entry point for the Tobimaru WiFi Watchdog daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/vkochetkov/tobimaru/internal/capture"
	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/logging"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/shutdown"
	"github.com/vkochetkov/tobimaru/internal/version"
)

// frameStatsInterval controls how often consumeFrames reports capture stats.
const frameStatsInterval = 5 * time.Second

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

	// Create capture pipeline with the configured logger.
	pipeline, err := capture.NewPipeline(cfg, logger)
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
		return pipeline.Stop(context.Background())
	})

	// Wire detection engine.
	engine := detector.NewEngine(cfg.Detection)
	slog.Info("detection engine created",
		"enabled", cfg.Detection.Enabled,
		"dedup_window", cfg.Detection.DedupWindow,
	)

	registerDetectionRules(engine, cfg.Detection)

	if cfg.Detection.Enabled && engine.RuleCount() == 0 {
		slog.Warn("detection enabled but no rules registered; alerts will not be generated")
	}

	// Track consumer goroutines so shutdown waits for their final log lines.
	var consumerWG sync.WaitGroup

	if cfg.Detection.Enabled {
		engine.Run(signalCtx, pipeline.Frames())
		consumerWG.Go(func() {
			consumeAlerts(signalCtx, engine.Alerts())
		})
	} else {
		// Detection disabled — continue with simple frame consumer for dev/debug.
		consumerWG.Go(func() {
			consumeFrames(signalCtx, pipeline.Frames())
		})
	}

	// Wait for consumer goroutines to drain their channels and log final
	// stats before shutdown completes. The hook respects the shutdown
	// context's deadline.
	sm.Register("consumer_stop", func() error {
		done := make(chan struct{})
		go func() {
			consumerWG.Wait()
			close(done)
		}()
		select {
		case <-done:
			return nil
		case <-time.After(10 * time.Second):
			return errors.New("consumer goroutines did not exit within 10s")
		}
	})

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
	var lastFrame *parser.ParsedFrame

	ticker := time.NewTicker(frameStatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("frame consumer stopped", "total_frames", count)
			return
		case frame, ok := <-frames:
			if !ok {
				slog.Info("frame consumer stopped", "total_frames", count)
				return
			}
			count++
			lastFrame = frame
		case <-ticker.C:
			if lastFrame != nil {
				slog.Debug("capture stats",
					"frames_received", count,
					"current_type", lastFrame.FrameType.String(),
					"current_channel", lastFrame.Channel,
				)
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
				slog.Info("alert consumer stopped", "total_alerts", count)
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

func registerDetectionRules(engine *detector.Engine, cfg config.DetectionConfig) {
	register := func(rule detector.Rule) {
		if err := engine.Register(rule); err != nil {
			slog.Error("failed to register detection rule",
				"rule", rule.Name(),
				"error", err,
			)
		}
	}

	if cfg.DeauthFlood.Enabled {
		register(&detector.DeauthFloodRule{})
	}

	if cfg.DisassocFlood.Enabled {
		register(&detector.DisassocFloodRule{})
	}

	if cfg.BeaconFlood.Enabled {
		register(&detector.BeaconFloodRule{})
	}

	if cfg.EvilTwin.Enabled {
		register(&detector.EvilTwinRule{})
	}

	if cfg.UnauthorizedDevice.Enabled {
		register(&detector.UnauthorizedDeviceRule{})
	}
}
