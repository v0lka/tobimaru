# Full Codebase Review — 2026-06-06

Comprehensive code review of the entire Tobimaru repository covering completeness,
correctness, and impact perspectives.

---

## Critical Issues (MUST FIX)

### 1. SSE Hub double-closes subscriber channels on shutdown (panic)

**Location:** [internal/api/sse.go#L113-L131, L165-L174](/Users/vkochetkov/Repositories/tobimaru/internal/api/sse.go)

**Problem:**
The SSE hub closes subscriber channels in two independent code paths:
- `unsubscribe` (via `sync.OnceFunc`) calls `close(sub.ch)` at line 128.
- `closeAll()` (called from `Run` defer) also calls `close(sub.ch)` at line 170.

On shutdown, `Hub.Run` exits (context canceled) and calls `closeAll()`, closing all
channels. Then HTTP handlers receive context cancellation, and their deferred
`unsubscribe` fires, calling `close(sub.ch)` on the same already-closed channel.
Closing a closed channel **panics** in Go. This can crash the process during
graceful shutdown.

**Fix:**
Remove `close(sub.ch)` from the `unsubscribe` closure. Let `closeAll` be the sole
owner of channel closure:

```go
unsub := sync.OnceFunc(func() {
    h.subsMu.Lock()
    delete(h.subs, id)
    h.subsMu.Unlock()
    // Do NOT close(sub.ch) here; closeAll handles it on hub shutdown.
})
```

For normal mid-session client disconnects, the subscriber is removed from the map
so `broadcast` won't send to it; the channel stays open but unreachable until
`closeAll` at hub shutdown.

---

### 2. SSE `"status"` payload is incompatible with `StatusResponse` — Status page crashes

**Location:**
- [cmd/tobimaru/main.go#L268-L284](/Users/vkochetkov/Repositories/tobimaru/cmd/tobimaru/main.go)
- [web/src/pages/Status.tsx#L20-L28](/Users/vkochetkov/Repositories/tobimaru/web/src/pages/Status.tsx)
- [web/src/api.ts#L51-L68](/Users/vkochetkov/Repositories/tobimaru/web/src/api.ts)

**Problem:**
The backend publishes periodic SSE `"status"` messages with only a partial map:

```go
st := map[string]any{
    "uptime_seconds":  int64(time.Since(startTime).Seconds()),
    "current_channel": 0,
}
// ... only adds stats.aps, stats.clients, subscribers.sse
```

But the frontend blindly replaces the full `StatusResponse` state with this partial
object:

```ts
if (eventName === "status") setStatus(data as StatusResponse);
```

After the first SSE tick:
- `status.capabilities` → `undefined`
- `caps.monitor_mode` → TypeError (cannot read property of undefined)
- `status.platform_limitations.length` → TypeError
- `status.stats.events_24h` → undefined

This crashes the Status page or renders it blank.

**Fix (choose one):**

**Option A — Backend sends full `StatusResponse` over SSE:**
Reuse the same data structure as `/api/status` so the frontend cast is valid.

**Option B — Frontend treats SSE `"status"` as a partial patch:**
```ts
useSSE(
  useCallback((eventName, data) => {
    if (eventName === "status") {
      const patch = data as Partial<StatusResponse>;
      setStatus((prev) => prev ? {
        ...prev,
        ...patch,
        stats: { ...prev.stats, ...(patch.stats ?? {}) },
        subscribers: { ...prev.subscribers, ...(patch.subscribers ?? {}) },
      } : prev);
    }
  }, []),
);
```

---

## Warnings (SHOULD FIX)

### 3. Monitor mode not reverted when capture handle creation fails

**Location:** [internal/capture/pipeline.go#L134-L143](/Users/vkochetkov/Repositories/tobimaru/internal/capture/pipeline.go)

**Problem:**
`Pipeline.Start` enables monitor mode, then opens the capture handle. If
`OpenCapture` fails (permissions, pcap error), the function returns an error
**without calling `DisableMonitor`**. This leaves the wireless interface stuck in
monitor mode, breaking the user's network connectivity.

**Fix:**
```go
handle, err := OpenCapture(iface, ccfg.Snaplen, *ccfg.Promiscuous, ccfg.Timeout, ccfg.BufferSize)
if err != nil {
    disableCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    if derr := p.monitor.DisableMonitor(disableCtx, iface); derr != nil {
        p.logger.Warn("failed to revert monitor mode after capture failure",
            "interface", iface, "error", derr)
    }
    return fmt.Errorf("failed to open capture on %s: %w", iface, err)
}
```

---

### 4. Detection engine has no concrete rules — detection is effectively a no-op

**Location:**
- [cmd/tobimaru/main.go#L140-L152](/Users/vkochetkov/Repositories/tobimaru/cmd/tobimaru/main.go)
- [configs/tobimaru.yaml#L42-L45](/Users/vkochetkov/Repositories/tobimaru/configs/tobimaru.yaml)

**Problem:**
`detection.enabled` defaults to `true` in the sample config, but no rules are ever
registered. The engine runs, prints a warning, but never generates any alerts.
Tobimaru does not perform intrusion detection in its current state.

**Fix:**
Either:
1. Set `detection.enabled: false` in `configs/tobimaru.yaml` until rules exist.
2. Or fail startup when `detection.enabled && RuleCount() == 0` to make the
   incomplete state explicit rather than silently running as a no-op.

---

### 5. Negative storage retention values silently disable pruning

**Location:** [internal/config/validation.go#L71-L79](/Users/vkochetkov/Repositories/tobimaru/internal/config/validation.go)

**Problem:**
`MaxSnapshots` and `MaxEvents` are not validated for negative values. A negative
`MaxSnapshots` causes `LIMIT ?` in SQLite to mean "no limit" — nothing is pruned.
A negative `MaxEvents` makes the `maxEvents > 0` guard false — events grow unbounded.

**Fix:**
Add validation:
```go
if cfg.Storage.MaxSnapshots < 0 {
    errs = append(errs, errors.New("storage.max_snapshots must be >= 0"))
}
if cfg.Storage.MaxEvents < 0 {
    errs = append(errs, errors.New("storage.max_events must be >= 0"))
}
```

---

## Suggestions (CONSIDER)

### 6. Use a cancelable context for storage migrations

**Location:** [internal/storage/sqlite.go#L47-L59](/Users/vkochetkov/Repositories/tobimaru/internal/storage/sqlite.go)

**Problem:**
`Open` uses `context.Background()` for pragmas and migrations. If the filesystem
or driver hangs, this blocks startup indefinitely with no cancellation path.

**Fix:**
Accept a context from the caller or use a bounded timeout:
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
```

---

### 7. Cross-compilation matrix omits darwin/amd64 mentioned in spec

**Location:**
- [specs/domains/build-and-versioning.md#L48-L57](/Users/vkochetkov/Repositories/tobimaru/specs/domains/build-and-versioning.md)
- [Makefile#L28-L33](/Users/vkochetkov/Repositories/tobimaru/Makefile)

**Problem:**
The build spec lists 4 targets (linux/amd64, linux/arm64, darwin/amd64,
darwin/arm64) but `Makefile` and CI only build 3 (no darwin/amd64).
Spec and implementation are out of sync.

**Fix:**
Update the spec to reflect current targets (3 platforms), or add the darwin/amd64
build if it's still needed.

---

### 8. Configuration spec missing `API` section from core types

**Location:**
- [specs/domains/configuration.md#L17-L25](/Users/vkochetkov/Repositories/tobimaru/specs/domains/configuration.md)
- [internal/config/config.go#L24-L33](/Users/vkochetkov/Repositories/tobimaru/internal/config/config.go)

**Problem:**
The configuration spec's "Core Types" snippet does not include `APIConfig`, even
though it's fully implemented and used. The spec lags the implementation.

**Fix:**
Add `API APIConfig \`yaml:"api"\`` to the spec's `Config` struct and document
`APIConfig` fields.

---

### 9. Storage spec missing session support and `ErrNotFound`

**Location:**
- [specs/domains/storage.md](/Users/vkochetkov/Repositories/tobimaru/specs/domains/storage.md)
- [internal/storage/storage.go#L13-L49](/Users/vkochetkov/Repositories/tobimaru/internal/storage/storage.go)

**Problem:**
The storage domain spec doesn't document the `Session` type, session CRUD methods,
or the `ErrNotFound` sentinel — all of which are implemented and depended upon by
the API authentication layer.

**Fix:**
Add `Session` struct, session methods, and `ErrNotFound` to
`specs/domains/storage.md`.

---

### 10. No end-to-end startup/shutdown integration test

**Location:** [cmd/tobimaru/main.go](/Users/vkochetkov/Repositories/tobimaru/cmd/tobimaru/main.go)

**Problem:**
Individual packages have strong unit tests, but there's no integration test that
exercises the full startup → wiring → graceful shutdown flow of the orchestrator.
A bug in wiring order or shutdown sequencing would only be caught manually.

**Fix:**
Factor `main()` into a `run(ctx, args) error` function and add an integration test
that boots with a minimal in-memory config, then cancels the context and asserts
clean shutdown within a timeout.

---

## Summary of Changes

- **SSE Hub (critical):** Double-close on shutdown will panic — need single-owner
  channel lifecycle.
- **SSE Status payload (critical):** Partial payload crashes the web dashboard;
  needs full payload or partial merge on the frontend.
- **Capture pipeline:** Missing cleanup of monitor mode on startup failure can brick
  the user's WiFi interface.
- **Detection engine:** Runs as no-op because no rules exist; sample config should
  reflect this.
- **Config validation:** Negative retention values bypass pruning silently.
- **Spec drift:** Multiple specs are behind the implementation (API config, storage
  sessions, build targets).
