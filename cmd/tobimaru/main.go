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

	"golang.org/x/crypto/bcrypt"

	"github.com/vkochetkov/tobimaru/internal/api"
	"github.com/vkochetkov/tobimaru/internal/capture"
	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/logging"
	"github.com/vkochetkov/tobimaru/internal/parser"
	"github.com/vkochetkov/tobimaru/internal/shutdown"
	"github.com/vkochetkov/tobimaru/internal/state"
	"github.com/vkochetkov/tobimaru/internal/storage"
	"github.com/vkochetkov/tobimaru/internal/version"
)

// frameStatsInterval controls how often consumeFrames reports capture stats.
const frameStatsInterval = 5 * time.Second

// pruneEventInterval is the number of stored events between PruneEvents
// calls in consumeAlerts. Pruning runs periodically rather than on every
// insert so that the cost of the DELETE-with-subquery scales with retention
// rather than ingest rate.
const pruneEventInterval uint64 = 100

func main() { //nolint:gocyclo // orchestrator with linear initialization sequence
	flagConfig := flag.String("config", "configs/tobimaru.yaml", "path to configuration file")
	flagVersion := flag.Bool("version", false, "print version and exit")
	flagHashPassword := flag.String("hash-password", "", "print bcrypt hash for the given plaintext password and exit")
	flag.Parse()

	if *flagVersion {
		fmt.Println(version.String())
		return
	}

	if *flagHashPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*flagHashPassword), bcrypt.DefaultCost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to hash password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(hash))
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

	// Open storage (early, before anything that writes to it).
	var repo storage.Repository
	if cfg.Storage.Enabled {
		repo, err = storage.Open(cfg.Storage)
		if err != nil {
			slog.Error("Failed to open storage", "error", err)
			os.Exit(1)
		}
		slog.Info("storage opened", "path", cfg.Storage.Path)
	}

	// Create state engine.
	var stateEngine *state.Engine
	if cfg.State.Enabled {
		stateEngine = state.NewEngine(cfg.State, cfg.Whitelist, logger)
		slog.Info("state engine created",
			"ttl", cfg.State.TTL,
			"sweep_interval", cfg.State.SweepInterval,
		)

		// Load persisted whitelist/blacklist from storage.
		if repo != nil {
			wl, wlErr := repo.ListWhitelist(context.Background())
			bl, blErr := repo.ListBlacklist(context.Background())
			if wlErr != nil {
				slog.Warn("failed to load whitelist from storage", "error", wlErr)
			}
			if blErr != nil {
				slog.Warn("failed to load blacklist from storage", "error", blErr)
			}
			if wlErr == nil && blErr == nil {
				stateEngine.Whitelist().LoadFromStorage(wl, bl)
				slog.Info("loaded persisted lists",
					"whitelist_entries", len(wl),
					"blacklist_entries", len(bl),
				)
			}
		}
	}

	// Wire detection engine (early, to fail fast if no rules are registered).
	engine := detector.NewEngine(cfg.Detection)
	slog.Info("detection engine created",
		"enabled", cfg.Detection.Enabled,
		"dedup_window", cfg.Detection.DedupWindow,
	)

	// TODO(phase-2.3): register attack-detection rules here
	// (deauth flood, disassoc flood, evil twin, ...).

	if cfg.Detection.Enabled && engine.RuleCount() == 0 {
		slog.Error("detection.enabled is true but no rules are registered; " +
			"set detection.enabled=false or register rules before starting")
		os.Exit(1)
	}

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

	if repo != nil {
		sm.Register("storage_close", func() error {
			return repo.Close()
		})
	}

	// Create the SSE hub when the API is enabled. The hub must exist before
	// the alert consumer starts so that early events are not dropped on the
	// floor.
	var apiHub *api.Hub
	if cfg.API.Enabled {
		apiHub = api.NewHub(logger)
	}

	// Track consumer goroutines so shutdown waits for their final log lines.
	var consumerWG sync.WaitGroup
	bufSize := cfg.Monitor.Capture.FrameBufferSize

	if cfg.Detection.Enabled && stateEngine != nil {
		// Both detection and state active: fan-out needed.
		detectorCh := make(chan *parser.ParsedFrame, bufSize)
		stateCh := make(chan *parser.ParsedFrame, bufSize)
		consumerWG.Go(func() {
			fanOut(signalCtx, pipeline.Frames(), detectorCh, stateCh)
		})
		engine.Run(signalCtx, detectorCh)
		consumerWG.Go(func() {
			consumeAlerts(signalCtx, engine.Alerts(), repo, cfg.Storage.MaxEvents, apiHub)
		})
		consumerWG.Go(func() {
			consumeStateFrames(signalCtx, stateCh, stateEngine)
		})
	} else if cfg.Detection.Enabled {
		// Detection only, no state engine.
		engine.Run(signalCtx, pipeline.Frames())
		consumerWG.Go(func() {
			consumeAlerts(signalCtx, engine.Alerts(), repo, cfg.Storage.MaxEvents, apiHub)
		})
	} else if stateEngine != nil {
		// State only, no detection.
		consumerWG.Go(func() {
			consumeStateFrames(signalCtx, pipeline.Frames(), stateEngine)
		})
	} else {
		// Neither: debug consumer.
		consumerWG.Go(func() {
			consumeFrames(signalCtx, pipeline.Frames())
		})
	}

	// Start eviction goroutine.
	if stateEngine != nil {
		consumerWG.Go(func() {
			stateEngine.RunEviction(signalCtx)
		})
	}

	// Start snapshot writer.
	if stateEngine != nil && repo != nil {
		consumerWG.Go(func() {
			runSnapshotWriter(signalCtx, stateEngine, repo,
				cfg.Storage.SnapshotInterval, cfg.Storage.MaxSnapshots)
		})
	}

	// Start auto-learning if enabled.
	if stateEngine != nil && cfg.Whitelist.AutoLearning.Enabled {
		consumerWG.Go(func() {
			lm := state.NewLearningMode(cfg.Whitelist.AutoLearning, stateEngine, logger)
			entries := lm.Run(signalCtx)
			if repo != nil && len(entries) > 0 {
				for _, e := range entries {
					if err := repo.SaveWhitelistEntry(signalCtx, e); err != nil {
						slog.Warn("failed to persist auto-learned whitelist entry", "error", err)
					}
				}
				slog.Info("auto-learning whitelist persisted", "entries", len(entries))
			}
		})
	}

	// Start the API server (REST + SSE + dashboard).
	startTime := time.Now()
	if cfg.API.Enabled && apiHub != nil {
		apiSrv, err := api.NewServer(cfg.API, api.Deps{
			Config:    cfg,
			State:     stateEngine,
			Repo:      repo,
			Detector:  engine,
			Pipeline:  pipeline,
			Hub:       apiHub,
			StartTime: startTime,
			Logger:    logger,
		})
		if err != nil {
			slog.Error("Failed to create API server", "error", err)
			os.Exit(1)
		}
		consumerWG.Go(func() { apiHub.Run(signalCtx) })
		consumerWG.Go(func() {
			if err := apiSrv.Run(signalCtx); err != nil {
				slog.Error("api server exited with error", "error", err)
			}
		})
		// Periodically publish state/status to SSE subscribers.
		consumerWG.Go(func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-signalCtx.Done():
					return
				case <-ticker.C:
					if !apiHub.HasSubscribers() {
						continue
					}
					if stateEngine != nil {
						apiHub.Publish(api.Message{Type: api.MessageTypeAP, Data: stateEngine.APs().All()})
						apiHub.Publish(api.Message{Type: api.MessageTypeClient, Data: stateEngine.Clients().All()})
					}
					apiHub.Publish(api.NewStatusMessage(apiSrv.StatusSnapshot(signalCtx)))
				}
			}
		})
		sm.Register("api_stop", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.API.ShutdownTimeout)
			defer cancel()
			return apiSrv.Shutdown(ctx)
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

// fanOut reads from a single source channel and distributes each frame
// to all provided sink channels. It closes all sinks when the source
// closes or ctx is canceled.
func fanOut(ctx context.Context, source <-chan *parser.ParsedFrame, sinks ...chan<- *parser.ParsedFrame) {
	defer func() {
		for _, s := range sinks {
			close(s)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-source:
			if !ok {
				return
			}
			for _, s := range sinks {
				select {
				case s <- frame:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// consumeStateFrames receives parsed frames and updates the state engine.
func consumeStateFrames(ctx context.Context, frames <-chan *parser.ParsedFrame, eng *state.Engine) {
	var count uint64
	for {
		select {
		case <-ctx.Done():
			slog.Info("state consumer stopped", "total_frames", count)
			return
		case frame, ok := <-frames:
			if !ok {
				slog.Info("state consumer stopped", "total_frames", count)
				return
			}
			count++
			eng.ProcessFrame(frame)
		}
	}
}

// runSnapshotWriter periodically persists state snapshots and prunes old ones.
func runSnapshotWriter(ctx context.Context, eng *state.Engine, repo storage.Repository, interval time.Duration, maxSnapshots int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := eng.Snapshot()
			if err := repo.SaveSnapshot(ctx, snap); err != nil {
				slog.Warn("failed to save state snapshot", "error", err)
				continue
			}
			pruned, err := repo.PruneSnapshots(ctx, maxSnapshots)
			if err != nil {
				slog.Warn("failed to prune old snapshots", "error", err)
			} else if pruned > 0 {
				slog.Debug("pruned old snapshots", "count", pruned)
			}
		}
	}
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
// them at appropriate levels based on severity. If a repository is provided,
// events are also persisted to storage and the events table is periodically
// pruned to maxEvents (when > 0). When a non-nil SSE hub is supplied, every
// alert is also broadcast to subscribed dashboard clients.
func consumeAlerts(ctx context.Context, alerts <-chan *detector.SecurityEvent, repo storage.Repository, maxEvents int, hub *api.Hub) { //nolint:gocyclo // logging + storage + hub fan-out is linear, not branching
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

			// Broadcast to dashboard subscribers if the API hub is available.
			if hub != nil {
				hub.Publish(api.NewEventMessage(event))
			}

			// Persist to storage if available.
			if repo != nil {
				if err := repo.SaveEvent(ctx, event); err != nil {
					slog.Warn("failed to persist security event", "error", err)
				} else if maxEvents > 0 && count%pruneEventInterval == 0 {
					if pruned, err := repo.PruneEvents(ctx, maxEvents); err != nil {
						slog.Warn("failed to prune old events", "error", err)
					} else if pruned > 0 {
						slog.Debug("pruned old events", "count", pruned)
					}
				}
			}
		}
	}
}
