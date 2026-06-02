// Package detector provides the WiFi intrusion detection engine, rule interface,
// and security event model for the Tobimaru WiFi Watchdog.
package detector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vkochetkov/tobimaru/internal/config"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

const maxDedupEntries = 10000

// dedupSweepFrameInterval is how often dispatch triggers an opportunistic
// dedup sweep, measured in frames processed. Faster than the time-based ticker
// on busy pipelines.
const dedupSweepFrameInterval = 1000

// ErrEngineStarted is returned by Register when the engine has already been
// started by Run; the rule list is immutable after Run is called.
var ErrEngineStarted = errors.New("detector: engine already started; cannot register more rules")

// Engine is the detection engine that aggregates detection rules, dispatches
// parsed 802.11 frames to all registered rules, deduplicates security events,
// and emits alerts on a channel.
type Engine struct {
	rules       []Rule                 // registered rules (immutable after Run)
	alerts      chan *SecurityEvent    // buffered output channel
	detCfg      config.DetectionConfig // full detection configuration
	dedupWindow time.Duration          // deduplication time window
	dedup       map[string]time.Time   // dedup cache (key → last emission time)
	mu          sync.Mutex             // guards dedup map
	started     atomic.Bool            // set true on first Run; rejects late Register
	frameCount  uint64                 // total frames processed; single-goroutine writer
}

// NewEngine creates a new detection engine from the detection configuration.
func NewEngine(cfg config.DetectionConfig) *Engine {
	bufSize := cfg.AlertBufferSize
	if bufSize <= 0 {
		bufSize = config.DefaultAlertBufferSize
	}
	dedupWindow := cfg.DedupWindow
	if dedupWindow <= 0 {
		dedupWindow = config.DefaultDedupWindow
	}
	return &Engine{
		alerts:      make(chan *SecurityEvent, bufSize),
		detCfg:      cfg,
		dedupWindow: dedupWindow,
		dedup:       make(map[string]time.Time),
	}
}

// Register adds a detection rule to the engine. The rule's Init method is
// called with the engine's configuration. Registration fails if a rule with
// the same name is already registered, if Init returns an error, or if the
// engine has already been started by Run (ErrEngineStarted).
// Must be called before Run.
func (e *Engine) Register(rule Rule) error {
	if e.started.Load() {
		return ErrEngineStarted
	}
	for _, r := range e.rules {
		if r.Name() == rule.Name() {
			return fmt.Errorf("rule %q is already registered", rule.Name())
		}
	}
	if err := rule.Init(e.detCfg); err != nil {
		return fmt.Errorf("rule %q init failed: %w", rule.Name(), err)
	}
	e.rules = append(e.rules, rule)
	return nil
}

// Run starts the detection engine dispatch goroutine. It reads parsed frames
// from the frames channel, dispatches them to all registered rules, collects
// events, applies deduplication, and emits alerts on the alerts channel.
// The goroutine exits when ctx is canceled or the frames channel is closed.
// The alerts channel is closed when the goroutine exits.
// Run returns immediately; the engine runs asynchronously.
//
// Subsequent calls to Run are no-ops and emit a warning. After Run is called,
// the rule list is immutable; Register returns ErrEngineStarted.
func (e *Engine) Run(ctx context.Context, frames <-chan *parser.ParsedFrame) {
	if !e.started.CompareAndSwap(false, true) {
		slog.Warn("detector: Run called more than once; ignoring")
		return
	}

	sweepInterval := max(e.dedupWindow, time.Second)
	ticker := time.NewTicker(sweepInterval)

	go func() {
		defer ticker.Stop()
		defer close(e.alerts)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.sweepDedup()
			case frame, ok := <-frames:
				if !ok {
					return
				}
				e.dispatch(frame)
			}
		}
	}()
}

// RuleCount returns the number of registered detection rules.
func (e *Engine) RuleCount() int {
	return len(e.rules)
}

// Alerts returns a read-only channel of security events emitted by the engine.
// The channel is closed when the engine's dispatch goroutine exits.
func (e *Engine) Alerts() <-chan *SecurityEvent {
	return e.alerts
}

// dispatch processes a single frame through all registered rules.
func (e *Engine) dispatch(frame *parser.ParsedFrame) {
	if frame == nil {
		slog.Warn("detector: received nil frame, skipping")
		return
	}

	e.frameCount++
	count := e.frameCount

	for _, rule := range e.rules {
		e.processRule(rule, frame)
	}

	// Periodic dedup sweep (faster than ticker for busy pipelines).
	if count%dedupSweepFrameInterval == 0 {
		e.sweepDedup()
	}
}

// processRule invokes a single rule's Process method with panic recovery.
func (e *Engine) processRule(rule Rule, frame *parser.ParsedFrame) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("detector: rule panicked",
				"rule", rule.Name(),
				"frame_type", frame.FrameType.String(),
				"panic", r,
			)
		}
	}()

	events := rule.Process(frame)
	for _, ev := range events {
		e.emit(ev)
	}
}

// emit sends a security event to the alerts channel after deduplication.
// If the channel is full, the event is dropped and a warning is logged.
func (e *Engine) emit(event *SecurityEvent) {
	if event == nil {
		return
	}

	key := dedupKey(event)
	e.mu.Lock()
	lastSeen, exists := e.dedup[key]
	if exists && time.Since(lastSeen) < e.dedupWindow {
		e.mu.Unlock()
		return // suppressed
	}
	e.dedup[key] = time.Now()
	e.mu.Unlock()

	select {
	case e.alerts <- event:
		// emitted successfully
	default:
		slog.Warn("detector: alert channel full, dropping event",
			"type", event.EventType,
			"severity", event.Severity.String(),
		)
	}
}

// dedupKey constructs a deduplication key from the event's type and MAC addresses.
// Hot-path: avoids fmt.Sprintf to reduce allocations on every emitted event.
func dedupKey(event *SecurityEvent) string {
	src := ""
	if event.SrcMAC != nil {
		src = event.SrcMAC.String()
	}
	bss := ""
	if event.BSSID != nil {
		bss = event.BSSID.String()
	}
	var b strings.Builder
	b.Grow(len(event.EventType) + len(src) + len(bss) + 2)
	b.WriteString(event.EventType)
	b.WriteByte(':')
	b.WriteString(src)
	b.WriteByte(':')
	b.WriteString(bss)
	return b.String()
}

// sweepDedup removes stale entries from the dedup map to prevent unbounded
// memory growth. Entries older than 2x the dedup window, or any entries if
// the map exceeds maxDedupEntries, are removed.
func (e *Engine) sweepDedup() {
	e.mu.Lock()
	defer e.mu.Unlock()

	cutoff := time.Now().Add(-2 * e.dedupWindow)
	for key, lastSeen := range e.dedup {
		if lastSeen.Before(cutoff) {
			delete(e.dedup, key)
		}
	}

	// If still too large after time-based cleanup, remove oldest entries.
	if len(e.dedup) > maxDedupEntries {
		type keyTime struct {
			key      string
			lastSeen time.Time
		}
		entries := make([]keyTime, 0, len(e.dedup))
		for k, v := range e.dedup {
			entries = append(entries, keyTime{k, v})
		}
		// Sort by oldest first and remove the oldest half.
		slices.SortFunc(entries, func(a, b keyTime) int {
			return a.lastSeen.Compare(b.lastSeen)
		})
		for i := range len(entries) / 2 {
			delete(e.dedup, entries[i].key)
		}
	}
}
