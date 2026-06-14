# API & Web Dashboard

## Purpose

Expose Tobimaru's runtime data — APs, clients, security events, statistics,
configuration, and live updates — over an HTTP REST surface and an embedded
single-page dashboard. The package gates writes behind role-based
authentication and broadcasts real-time updates through Server-Sent Events.

## Key Files

- `internal/api/server.go` — chi router, middleware stack, server lifecycle.
- `internal/api/middleware.go` — request logger, panic recoverer, CORS, no-cache.
- `internal/api/auth.go` — login/logout, session cookie, role guards, pruner.
- `internal/api/sse.go` — non-blocking fan-out hub for SSE messages.
- `internal/api/handlers_status.go` — `GET /api/status` (public).
- `internal/api/handlers_state.go` — `GET /api/aps`, `GET /api/clients`.
- `internal/api/handlers_events.go` — `GET /api/events`, `GET /api/stats`.
- `internal/api/handlers_lists.go` — whitelist & blacklist CRUD.
- `internal/api/handlers_config.go` — `GET /api/config` (read), `PUT /api/config` (mutable allowlist).
- `internal/api/handlers_stream.go` — `GET /api/stream` (SSE endpoint).
- `internal/api/dto.go` — JSON DTOs for state and event payloads.
- `internal/api/errors.go` — RFC 7807 problem+json envelopes.
- `internal/api/web/embed.go` — `go:embed all:dist` SPA handler with placeholder fallback.
- `internal/api/web/dist/` — built SPA bundle (committed).
- `web/` — SPA source tree (React 19 + Vite + TypeScript). Built by `make web`.
- `web/src/assets/` — static assets imported by components (Vite adds content hashes at build time).

## Core Types

```go
type Server struct { /* chi router + http.Server lifecycle */ }
type Deps struct {
    Config    *config.Config
    State     *state.Engine
    Repo      storage.Repository
    Detector  *detector.Engine
    Pipeline  *capture.Pipeline
    Hub       *Hub
    StartTime time.Time
    Logger    *slog.Logger
}

type Hub struct { /* non-blocking fan-out for SSE clients */ }
type Message struct { Type string; Data any }
```

## Flow

```
HTTP request
   │
   ▼
chi.Router
   ├── middleware: recoverer → requestLogger → CORS → noCacheAPI
   │
   ├── public:        GET /api/status
   │                  POST /api/login, POST /api/logout
   │
   ├── requireAuth:   GET  /api/{aps,clients,events,stats,whitelist,blacklist,config,stream}
   │
   ├── requireAdmin:  PUT    /api/config
   │                  POST   /api/{whitelist,blacklist}
   │                  DELETE /api/{whitelist,blacklist}/{mac}
   │
   └── NotFound:      api/* → problem+json 404
                      else  → SPA index.html (web.Handler)
```

Detection alerts are pushed by `cmd/tobimaru/main.go` into
`Hub.Publish(api.NewEventMessage(event))` from `consumeAlerts`. SSE clients
subscribe in `handleStream`, receive a `hello` message, then the broadcast
stream plus a 15 s comment keepalive.

## Invariants

- The package depends on `config`, `state`, `storage`, `detector`, `capture`,
  `version`, and `logging` — never on `cmd/tobimaru`.
- `auth.enabled = true` requires `storage.enabled = true` (sessions live in
  the SQLite `sessions` table). `NewServer` rejects any other combination.
- Every `/api/*` failure response uses the `problemDetails` envelope and the
  `application/problem+json` content type.
- Admin-only routes never run before `requireAuth`; both middleware layers
  are mounted in `buildRouter`.
- The SSE broadcaster never blocks on a slow subscriber — full per-subscriber
  channels drop the message and log a warning.
- Session tokens are 32 random bytes from `crypto/rand`, base64-url encoded.
- Password verification always runs through `bcrypt.CompareHashAndPassword`.
- The YAML config file is **read-only** at runtime; `PUT /api/config` modifies
  in-memory state and the SQLite KV store, never the file on disk.
- The mutable allowlist for `PUT /api/config` is exactly:
  `log_level`, `detection_enabled`, `detection_dedup_window`. Any other key
  returns 400 with `errTypeUnsupportedField`.
- SPA caching policy: `/assets/*` files carry content hashes in filenames and
  are served with `Cache-Control: public, max-age=31536000, immutable`.
  Root-level files (`logo-128.png`, `favicon.ico`, etc.) are served with
  `Cache-Control: no-cache` (always revalidate). `index.html` is also
  `no-cache` to ensure browsers always fetch the latest entry point.

## Configuration

`api:` section in YAML; defaults applied by `internal/config/defaults.go`:

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` | master switch |
| `listen` | `127.0.0.1:8080` | use a reverse proxy for remote access |
| `read_timeout` | `15s` | applied to header + body read |
| `write_timeout` | `30s` | overridden per-request for SSE |
| `idle_timeout` | `60s` | keep-alive idle window |
| `shutdown_timeout` | `5s` | graceful HTTP shutdown deadline |
| `cors.allowed_origins` | `[]` | empty = same-origin only |
| `auth.enabled` | `false` | when `false` every request is admin |
| `auth.session_ttl` | `24h` | absolute session expiry |
| `auth.admin_password_hash` | — | required when auth enabled (bcrypt) |
| `auth.user_password_hash` | — | optional read-only account |
| `auth.cookie_secure` | `true` | Secure attribute on session cookie |

## Extension Points

- **New endpoint**: add a handler under `internal/api/` and register it in
  `Server.buildRouter` inside the appropriate group (public, auth, admin).
- **New SSE message type**: add a constant in `sse.go`, publish via
  `Hub.Publish`, and handle the matching `eventName` in
  `web/src/sse.ts`.
- **New mutable config field**: append the JSON key to `mutableKeys` in
  `handlers_config.go`, decode it in `handlePutConfig`, persist with the
  KV store, and apply at runtime via the relevant package's setter.
- **New SPA page**: add `web/src/pages/<Page>.tsx`, a route in `App.tsx`,
  and a tab in the nav `TABS` array. Run `make web` to refresh
  `internal/api/web/dist/`.

## Related Specs

- [Contract: API ↔ Internal](../contracts/api-internal.md) — every route, DTO, and error.
- [Contract: Main ↔ Internal](../contracts/main-internal.md) — wiring of `api.Server` from `cmd/tobimaru`.
- [Architecture: Layers](../architecture/layers.md) — package dependency rules.
- [ADR-005](../decisions/005-chi-spa-sse.md) — chi / React SPA / SSE choice.
- [Storage](storage.md) — sessions table and Session type.
- [Detection](detection.md) — security event source for SSE event broadcasts.
- [State](state.md) — APs, clients, whitelist/blacklist data sources.
