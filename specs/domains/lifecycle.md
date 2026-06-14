# Lifecycle (Graceful Shutdown)

## Purpose

Manages the application lifecycle: blocks on OS signals (SIGINT, SIGTERM), then executes registered cleanup hooks in order to shut down gracefully.

## Key Files

- `internal/shutdown/shutdown.go` — `Manager` struct, `Hook` type, `NewManager()`, `Register()`, `WaitForSignal()`, `Shutdown()`
- `internal/shutdown/shutdown_test.go` — unit tests: LIFO order, error aggregation, timeout, concurrent registration, signal delivery
- `cmd/tobimaru/main.go` — wires `shutdown.Manager` into the main orchestration flow

## Core Types

```go
type Hook struct {
    Name string
    Fn   func(context.Context) error
}

type Manager struct {
    mu           sync.Mutex
    hooks        []Hook
    signals      []os.Signal
    stopFunc     context.CancelFunc // releases signal notification resources
    shutdownOnce sync.Once          // ensures Shutdown runs exactly once
    shutdownErr  error              // captured error from first invocation
}
```

**Key functions:**

```go
func NewManager() *Manager                                    // default signals: SIGINT, SIGTERM
func (m *Manager) Register(name string, fn func(context.Context) error)     // thread-safe hook registration
func (m *Manager) WithSignals(signals ...os.Signal) *Manager // builder-pattern signal configuration
func (m *Manager) WaitForSignal(ctx context.Context) context.Context  // returns ctx canceled on signal
func (m *Manager) Shutdown(ctx context.Context) error        // runs hooks LIFO with deadline
```

## Flow

### Startup (in `cmd/tobimaru/main.go`)

```
shutdown.NewManager()
  ├─ signals: [SIGINT, SIGTERM]
  └─ returns *Manager

// Components register their cleanup during initialization:
sm.Register("component_name", func(ctx context.Context) error {
    // cleanup logic, can check ctx.Done() for timeout
    return nil
})
```

### Signal handling

```
sm.WaitForSignal(context.Background())
  └─► signal.NotifyContext(ctx, signals...)
        └─ Returns context canceled when signal arrives

main goroutine blocks on: <-signalCtx.Done()
```

### Shutdown

```
sm.Shutdown(shutdownCtx)  // shutdownCtx has 30-second overall timeout
  │
  ├─► Copy hooks slice (thread-safe under mutex)
  │
  └─► For each hook in REVERSE registration order (LIFO) via slices.Backward:
        │
        ├─► Create per-hook context with 10s timeout: context.WithTimeout(ctx, 10*time.Second)
        ├─► Launch goroutine: h.Fn(hookCtx)
        ├─► Wait on select:
        │     ├─ hook returns error → accum in errs, continue to next hook
        │     ├─ hook returns nil     → continue to next hook
        │     └─ per-hook ctx.Done() → accum ctx.Err(), continue to next hook
        │
        └─► After all hooks: return errors.Join(errs...)
```

## Invariants

- Hooks always execute in **reverse registration order** (LIFO) via `slices.Backward`: last registered runs first
- Each hook is given a per-hook sub-context with a 10-second timeout (`context.WithTimeout`), independent of the parent deadline — a slow hook does NOT starve subsequent hooks
- If a per-hook timeout expires, the error is accumulated and execution continues to the next hook
- `Shutdown()` is idempotent via `sync.Once` — subsequent calls return the cached result of the first invocation
- Errors from hooks are aggregated with `errors.Join` — a failure in one hook does NOT prevent subsequent hooks from running
- `Register()` is thread-safe (protected by `sync.Mutex`)
- Default signals are `os.Interrupt` (SIGINT) and `syscall.SIGTERM`
- Shutdown timeout is controlled by the caller (30 seconds in `cmd/tobimaru/main.go`)

## Configuration

No direct configuration — the timeout is set by the caller when creating the `shutdownCtx`:

```go
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
```

## Extension Points

- **Adding cleanup in a new component:** call `sm.Register("name", cleanupFn)` during initialization in `main.go`
- **Changing signals:** use `WithSignals()` before `WaitForSignal()` — e.g., `sm.WithSignals(syscall.SIGUSR1, os.Interrupt).WaitForSignal(ctx)`
- **Adding pre-shutdown logic:** insert code between `<-signalCtx.Done()` and `sm.Shutdown()` in `main.go`
- **Making timeout configurable:** add a `shutdown.timeout` field to `config.Config` and pass it to `context.WithTimeout`

## Related Specs

- [Architecture: Layers](../architecture/layers.md) — where lifecycle fits in the package hierarchy
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — how main.go wires lifecycle with other packages
