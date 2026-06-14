// Package shutdown provides graceful shutdown via OS signals and cleanup hooks.
package shutdown

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"
)

// Hook represents a cleanup function to be executed during shutdown.
// The function receives a per-hook context that is canceled when the
// hook's time budget expires, allowing the hook to abort early.
type Hook struct {
	Name string
	Fn   func(context.Context) error
}

// Manager coordinates graceful shutdown by waiting for OS signals
// and executing registered cleanup hooks in reverse order.
type Manager struct {
	mu           sync.Mutex
	hooks        []Hook
	signals      []os.Signal
	stopFunc     context.CancelFunc // releases signal notification resources
	shutdownOnce sync.Once
	shutdownErr  error
}

// NewManager creates a new shutdown Manager that listens for SIGINT and SIGTERM.
func NewManager() *Manager {
	return &Manager{
		signals: []os.Signal{os.Interrupt, syscall.SIGTERM},
	}
}

// Register adds a cleanup hook. Hooks are executed in reverse registration
// order during shutdown (LIFO), so that resources created later are cleaned
// up first. The hook function receives a context that is canceled when its
// per-hook time budget (10s) expires.
func (m *Manager) Register(name string, fn func(context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = append(m.hooks, Hook{Name: name, Fn: fn})
}

// WithSignals configures which OS signals trigger shutdown.
// Must be called before WaitForSignal.
func (m *Manager) WithSignals(signals ...os.Signal) *Manager {
	m.mu.Lock()
	m.signals = signals
	m.mu.Unlock()
	return m
}

// WaitForSignal blocks until one of the configured signals is received.
// It returns a context that is canceled when the signal arrives.
func (m *Manager) WaitForSignal(ctx context.Context) context.Context {
	notifyCtx, stop := signal.NotifyContext(ctx, m.signals...)
	m.mu.Lock()
	m.stopFunc = stop
	m.mu.Unlock()
	return notifyCtx
}

// Shutdown executes all registered cleanup hooks in reverse registration
// order (LIFO). It respects the given context's deadline and aggregates
// errors from all hooks. Shutdown is safe to call multiple times; subsequent
// calls return the result of the first invocation.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.shutdownOnce.Do(func() {
		m.shutdownErr = m.doShutdown(ctx)
	})
	return m.shutdownErr
}

// doShutdown contains the actual shutdown logic invoked exactly once.
// Each hook gets its own per-hook deadline so a slow hook cannot skip
// all remaining hooks in the chain.
func (m *Manager) doShutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.stopFunc != nil {
		m.stopFunc()
	}
	hooks := make([]Hook, len(m.hooks))
	copy(hooks, m.hooks)
	m.mu.Unlock()

	var errs []error

	// Execute hooks in reverse order (LIFO). A per-hook sub-context with
	// a generous budget ensures one slow hook doesn't starve the rest.
	for _, hook := range slices.Backward(hooks) {
		hookCtx, hookCancel := context.WithTimeout(ctx, 10*time.Second)
		done := make(chan error, 1)
		go func(h Hook) {
			done <- h.Fn(hookCtx)
		}(hook)

		select {
		case err := <-done:
			if err != nil {
				errs = append(errs, err)
			}
		case <-hookCtx.Done():
			errs = append(errs, fmt.Errorf("hook %q: %w", hook.Name, hookCtx.Err()))
		}
		hookCancel()
	}

	return errors.Join(errs...)
}
