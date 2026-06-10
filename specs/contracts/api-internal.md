# Contract: API ↔ Internal Packages

## Boundary Rule

`internal/api` consumes types from `internal/{config,state,storage,detector,capture,version,logging}` and exposes a single HTTP surface. The package is consumed only by `cmd/tobimaru`. No internal package other than `cmd/tobimaru` may import `internal/api`.

## Interfaces

| Interface | Package | Consumed By | Purpose |
|-----------|---------|-------------|---------|
| `api.NewServer(cfg APIConfig, deps Deps) (*Server, error)` | `internal/api` | `cmd/tobimaru` | Build the HTTP server and chi router |
| `api.Server.Run(ctx) error` | `internal/api` | `cmd/tobimaru` | Listen and serve until ctx is canceled |
| `api.Server.Shutdown(ctx) error` | `internal/api` | `cmd/tobimaru` | Graceful HTTP shutdown |
| `api.NewHub(logger) *Hub` | `internal/api` | `cmd/tobimaru` | Build SSE fan-out broadcaster |
| `api.Hub.Run(ctx)` | `internal/api` | `cmd/tobimaru` | Drain publish queue and broadcast |
| `api.Hub.Publish(Message)` | `internal/api` | `cmd/tobimaru` | Push an event/state update to subscribers |
| `api.NewEventMessage(payload) Message` | `internal/api` | `cmd/tobimaru` | Wrap a security event in an SSE message |
| `storage.Repository.{Create,Get,Delete}Session, PruneExpiredSessions` | `internal/storage` | `internal/api` | Session-cookie persistence |

## HTTP Surface

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/status` | public | Version, uptime, capabilities, stats. |
| POST | `/api/login` | public | Body: `{username, password}`. Sets `tobimaru_session` cookie. |
| POST | `/api/logout` | public | Clears cookie and deletes the session row. |
| GET | `/api/aps` | user | Filters: `ssid`, `channel`, `since`. |
| GET | `/api/clients` | user | Filters: `associated`, `bssid`, `since`. |
| GET | `/api/events` | user | Filters: `since`, `until`, `event_type`, `min_severity`, `limit`, `offset`. |
| GET | `/api/stats` | user | Query: `window_seconds` (default 86400, max 604800). |
| GET | `/api/whitelist` | user | List entries. |
| POST | `/api/whitelist` | admin | Body: `{mac, ssid?, comment?}`. |
| DELETE | `/api/whitelist/{mac}` | admin | Remove entry. |
| GET | `/api/blacklist` | user | List entries. |
| POST | `/api/blacklist` | admin | Body: `{mac, reason?, comment?}`. |
| DELETE | `/api/blacklist/{mac}` | admin | Remove entry. |
| GET | `/api/config` | user | Effective config (secrets redacted) + mutable values. |
| PUT | `/api/config` | admin | Patch keys: `log_level`, `detection_enabled`, `detection_dedup_window`. |
| GET | `/api/stream` | user | SSE: events, state, status; 15 s keepalive. |
| GET | `/*` | public | SPA fallback (`internal/api/web/dist/index.html`). |

## DTOs

Every response on success is JSON with the shape defined in
`internal/api/dto.go` (APInfo, ClientInfo, SecurityEvent, WhitelistEntry,
BlacklistEntry) wrapped in:

```json
{ "items": [...], "total": <int64> }
```

`/api/status` returns `statusResponse` (see `handlers_status.go`).
`/api/stats` returns `statsResponse` with `by_type`, `by_severity`, and
`per_hour` arrays.

## Error Envelope

Every non-2xx response uses RFC 7807-style problem+json:

```json
{ "type": "<slug>", "title": "<status text>", "status": <int>, "detail": "<human readable>" }
```

Stable `type` slugs:
`bad_request`, `unauthorized`, `forbidden`, `not_found`,
`method_not_allowed`, `internal_error`, `unsupported_field`,
`storage_disabled`, `state_disabled`, `detection_disabled`.

## Authentication

- `POST /api/login` validates credentials with `bcrypt.CompareHashAndPassword`.
- Sessions are stored in SQLite (`sessions` table, schema v2). Token = 32
  random bytes base64-url encoded, set in an HttpOnly + SameSite=Strict
  cookie named `tobimaru_session`.
- `requireAuth` middleware looks up the cookie, rejects with 401 when
  missing/invalid/expired (best-effort cleanup of expired rows).
- `requireAdmin` runs after `requireAuth`; rejects user-role sessions with 403.
- A 5-minute background goroutine prunes expired sessions.
- When `auth.enabled = false`, every request runs as a synthetic admin.

## SSE

- `Content-Type: text/event-stream`.
- Each subscriber has a per-connection bounded channel; slow subscribers
  drop messages, never block the broadcaster.
- Message types: `event` (security events), `status` (status updates),
  `ap`, `client`, plus `hello` once on connect.
- `: keepalive` comment lines are emitted every 15 s.

## Data Flow Across Boundary

```
detector.Engine.Alerts() ─► consumeAlerts (in cmd/tobimaru)
                                ├── slog
                                ├── repo.SaveEvent (storage)
                                └── apiHub.Publish (api/sse.go)
                                          │
                                          ▼
                                    Hub.Run fan-out
                                          │
                                          ▼
                                handleStream → SSE wire
```

The state engine, repo, pipeline, and detector are read-only (or via their
own thread-safe APIs) from inside handlers — no background mutation runs in
the api package.

## Error Propagation

- Handler panics: `recoverer` middleware logs stack and replies with
  `internal_error` 500.
- Storage failures: 500 `internal_error`. The daemon does NOT crash.
- Validation failures: 400 `bad_request` (or `unsupported_field`).
- Unauthenticated request: 401 `unauthorized`.
- Wrong role: 403 `forbidden`.
- Disabled subsystem (state/detection/storage off): 503 with the matching
  slug so the SPA can degrade gracefully.

## Breaking Change Checklist

If you add a new route:
- [ ] Document it in this file's HTTP surface table.
- [ ] Add a corresponding helper in `web/src/api.ts` and a UI binding.
- [ ] If admin-only, mount it inside the `requireAdmin` group.

If you change a DTO:
- [ ] Update `internal/api/dto.go` and the matching `web/src/api.ts` interface.
- [ ] Update this contract's example shape.

If you add a new SSE message type:
- [ ] Add a constant in `internal/api/sse.go`.
- [ ] Add an event listener in `web/src/sse.ts`.
- [ ] Document the type here.

If you change auth semantics:
- [ ] Update `domains/api.md` invariants.
- [ ] Update `Authentication` section above.
- [ ] Update `configs/tobimaru.yaml` sample.
