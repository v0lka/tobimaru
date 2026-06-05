# Phase 4 — REST API & Web Dashboard

## Context

The project roadmap (`docs/development/wifi-watchdog-roadmap.md`) defines Phase 4 as the
mandatory feature set that exposes captured/detected data over HTTP and through an
embedded single-page dashboard. Phases 0–3 and 5 already provide the data sources
(`internal/state`, `internal/detector`, `internal/storage`, `internal/capture`,
`internal/platform`). Today the daemon only logs events and persists them; there is
no way for an operator to inspect the radio map, browse alerts, edit the whitelist,
or monitor agent status without inspecting the SQLite file directly.

This plan implements **all twelve roadmap tasks 4.1–4.12** in a single coherent
deliverable so the resulting binary fulfils the Phase 4 Definition of Done:
documented REST endpoints, real-time event streaming under one second,
single-binary deployment with embedded SPA, role-based auth, and a working
dashboard for environment map / events / statistics / settings / status.

## Architectural Decisions (confirmed with user)

- **SPA**: React 19 + Vite + TypeScript, Tailwind for styling, Recharts for graphs.
- **Router**: `github.com/go-chi/chi/v5` (with chi middlewares for recovery & request logging).
- **Auth**: token-based sessions stored in SQLite, HttpOnly cookie, roles `admin`/`user`,
  passwords hashed with `bcrypt` (`golang.org/x/crypto/bcrypt`).
- **Real-time**: Server-Sent Events on `GET /api/stream`, 15 s keepalive.
- **Bind**: HTTP only, default `127.0.0.1:8080`, configurable via YAML.
- **Build**: SPA built into `web/dist/` and **committed**; `make build` works without
  Node. `make web` rebuilds the bundle. CI runs both. `web/dist/` is embedded with
  `go:embed`.

## New Package & File Layout

```
cmd/tobimaru/main.go                         (modified — wire api.Server)
internal/api/                                (new package)
    server.go                                 chi router, lifecycle, embedded FS
    middleware.go                             logging, recovery, CORS, auth gate
    auth.go                                   login/logout, session issue/verify, role checks
    sse.go                                    Hub, Broadcaster, subscriber lifecycle
    handlers_status.go                        GET /api/status
    handlers_state.go                         GET /api/aps, /api/clients
    handlers_events.go                        GET /api/events, /api/stats
    handlers_lists.go                         GET/POST/DELETE /api/whitelist, /api/blacklist
    handlers_config.go                        GET/PUT /api/config (PUT scoped to mutable keys)
    handlers_stream.go                        GET /api/stream (SSE)
    dto.go                                    JSON DTOs (APInfo/ClientInfo/Event wrappers)
    errors.go                                 problem-json error helper
    server_test.go, *_test.go                 httptest-based handler tests
internal/api/web/
    embed.go                                  go:embed web/dist/* + SPA fallback
    embed_test.go                             smoke test that index.html is reachable

internal/storage/schema.go                   (modified — schema_version 2: sessions table)
internal/storage/sqlite.go                   (modified — session methods)
internal/storage/storage.go                  (modified — Session* on Repository)

internal/config/config.go                    (modified — APIConfig struct)
internal/config/defaults.go                  (modified — API defaults)
internal/config/validation.go                (modified — listen/timeout/auth checks)
configs/tobimaru.yaml                        (modified — api: section sample)

web/                                          (new — SPA source tree)
    package.json, vite.config.ts, tsconfig.json, index.html, tailwind.config.ts
    src/main.tsx, src/App.tsx, src/api.ts, src/auth.tsx, src/sse.ts
    src/pages/Login.tsx                       login form
    src/pages/Map.tsx                         task 4.8 — APs+clients table/grid, live updates
    src/pages/Events.tsx                      task 4.9 — events feed + filters
    src/pages/Stats.tsx                       task 4.10 — charts (recharts) over /api/stats
    src/pages/Settings.tsx                    task 4.11 — config view, whitelist/blacklist CRUD
    src/pages/Status.tsx                      task 4.12 — uptime, channel, capabilities
    src/components/...                        shared UI primitives
    dist/                                     committed Vite output, embedded by Go

specs/architecture/layers.md                 (modified — add internal/api node)
specs/contracts/main-internal.md             (modified — add api.NewServer/Run/Stop)
specs/contracts/api-internal.md              (new — API contract: routes, DTOs, errors)
specs/domains/api.md                         (new — domain spec for HTTP layer)
specs/decisions/005-chi-spa-sse.md           (new — ADR for router/SPA/SSE choices)
specs/INDEX.md                               (modified — index the new specs)

Makefile                                     (modified — `make web`, `make build` deps)
.github/workflows/ci.yml                     (modified — install Node, run `make web`)
go.mod / go.sum                              (modified — chi/v5, bcrypt)
.gitignore                                   (modified — node_modules; keep web/dist tracked)
```

## Implementation Tasks (mapped to roadmap 4.1–4.12)

### Task A — Configuration foundation (prereq for 4.1)
- Add `APIConfig` to `internal/config/config.go`:
  ```go
  type APIConfig struct {
      Enabled         bool          `yaml:"enabled"`
      Listen          string        `yaml:"listen"`           // default "127.0.0.1:8080"
      ReadTimeout     time.Duration `yaml:"read_timeout"`     // default 15s
      WriteTimeout    time.Duration `yaml:"write_timeout"`    // default 30s
      IdleTimeout     time.Duration `yaml:"idle_timeout"`     // default 60s
      ShutdownTimeout time.Duration `yaml:"shutdown_timeout"` // default 5s
      CORS            CORSConfig    `yaml:"cors"`
      Auth            AuthConfig    `yaml:"auth"`
  }
  type AuthConfig struct {
      Enabled           bool          `yaml:"enabled"`         // default true
      SessionTTL        time.Duration `yaml:"session_ttl"`     // default 24h
      AdminPasswordHash string        `yaml:"admin_password_hash"`
      UserPasswordHash  string        `yaml:"user_password_hash"`
  }
  type CORSConfig struct {
      AllowedOrigins []string `yaml:"allowed_origins"` // empty → same-origin only
  }
  ```
- Validation: when `api.enabled && auth.enabled`, require at least
  `admin_password_hash` to be a valid bcrypt hash; reject empty `listen` or
  non-positive timeouts. Sentinel errors: `ErrInvalidAPIListen`,
  `ErrInvalidAPITimeout`, `ErrMissingAdminHash`.
- Update `configs/tobimaru.yaml` with a commented sample `api:` block.

### Task B — Storage: sessions (prereq for 4.6)
- Bump `schemaVersion` to 2 in `internal/storage/schema.go`. Add migration block
  (idempotent `CREATE TABLE IF NOT EXISTS sessions ...`) that runs when the
  current DB is on version 1.
- Schema:
  ```sql
  CREATE TABLE sessions (
      token TEXT PRIMARY KEY,
      role  TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
  );
  CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
  ```
- Extend `Repository` interface with:
  `CreateSession`, `GetSession`, `DeleteSession`, `PruneExpiredSessions`.
  Implement on `SQLiteRepository`. Tokens are 32 random bytes from `crypto/rand`,
  base64-url encoded by the API layer (storage stays neutral).

### Task 4.1 — HTTP server, routing, middleware
- `internal/api/server.go`:
  ```go
  type Server struct { ... }
  func NewServer(cfg config.APIConfig, deps Deps) (*Server, error)
  func (s *Server) Run(ctx context.Context) error
  func (s *Server) Shutdown(ctx context.Context) error
  ```
  `Deps` is a struct of pointers/interfaces: `*state.Engine`, `storage.Repository`,
  `*detector.Engine`, `*capture.Pipeline`, `*config.Config`, `*slog.Logger`.
- Route mounting with chi:
  ```
  r.Use(middleware.RequestID, middleware.RealIP, mw.Logger, mw.Recovery, mw.CORS)
  r.Get("/api/status",   ...)         // public (no auth)
  r.Post("/api/login",   ...)
  r.Post("/api/logout",  ...)
  r.Group(authUser){     /api/aps, /api/clients, /api/events, /api/stats,
                          /api/whitelist, /api/blacklist, /api/config (GET),
                          /api/stream }
  r.Group(authAdmin){    /api/whitelist (POST/DELETE), /api/blacklist (POST/DELETE),
                          /api/config (PUT) }
  r.NotFound(spaFallback)            // serve index.html for non-/api routes
  r.Get("/assets/*", staticHandler)
  ```
- `middleware.go`:
  - structured request logger using existing `*slog.Logger` (method, path, status, duration, request_id).
  - panic recovery → 500 + slog.Error.
  - CORS: same-origin if `AllowedOrigins` empty; else permissive list.
  - JSON content-type helper, `writeJSON` / `writeProblem` (RFC 7807).

### Task 4.6 — Authentication & authorization
- `auth.go`:
  - `POST /api/login` body `{ "username": "admin"|"user", "password": "..." }`.
    Look up bcrypt hash from `cfg.API.Auth`, `bcrypt.CompareHashAndPassword`.
    On success: generate token, persist via `repo.CreateSession`, set
    `Set-Cookie: tobimaru_session=<tok>; Path=/; HttpOnly; SameSite=Strict[; Secure]`.
    Return `{ "role": "admin" }`.
  - `POST /api/logout`: read cookie, `repo.DeleteSession`, expire cookie.
  - `authUser` / `authAdmin` middleware: read cookie → `repo.GetSession` →
    check expiry & role; reject with 401 / 403 (problem+json).
  - Background goroutine: call `repo.PruneExpiredSessions` every 5 min;
    started by `Server.Run` and stopped via context.
- When `api.auth.enabled=false`, all routes act as if authenticated `admin`
  (useful for local dev / tests).

### Task 4.4 — GET /api/status
- Response payload (DTO):
  ```json
  {
    "version": "...", "commit": "...", "date": "...",
    "uptime_seconds": 12345,
    "current_channel": 6,
    "monitor_interface": "wlan0",
    "capabilities": { "monitor_mode": true, "frame_injection": false, ... },
    "platform_limitations": ["..."],
    "stats": { "aps": 12, "clients": 41, "events_total": 87, "events_24h": 4 }
  }
  ```
- Sources: `version` package, `time.Since(startTime)`, `pipeline.Capabilities()`,
  state engine maps, `repo.CountEvents`. Current channel obtained via a small
  `Pipeline.CurrentChannel() int` getter (added on `ChannelHopper` and surfaced
  through Pipeline). When hopping is disabled, return the configured channel
  (or 0).
- Public route — no auth, no SSE; safe data only.

### Task 4.2 — GET /api/aps, /api/clients, /api/events
- `/api/aps` → `state.Engine.APs().All()` mapped to `APDTO` with hex-formatted
  MACs and ISO-8601 timestamps; supports `?ssid=`, `?channel=`, `?since=`.
- `/api/clients` → `state.Engine.Clients().All()`; supports `?associated=true`,
  `?bssid=`.
- `/api/events` → `repo.ListEvents(filter)` using existing `EventFilter`;
  query params: `since`, `until`, `event_type`, `min_severity`, `limit`
  (cap 1000), `offset`. Returns `{ "items": [...], "total": <CountEvents> }`.

### Task 4.3 — Config### Task 4.3 — Config & whitelist/blacklist endpoints
- `GET /api/config`: returns the loaded `*config.Config` minus secrets
  (`auth.admin_password_hash`, `auth.user_password_hash` are redacted to `"***"`),
  serialized through DTO. `user` and `admin` may both read.
- `PUT /api/config` (admin): accepts a JSON patch with the small **mutable**
  whitelist of keys:
  - `detection.enabled`
  - `detection.dedup_window`
  - `log.level`
  Mutable values are persisted to the SQLite `config` KV store and applied at
  runtime (logger level via `slog.SetLogLoggerLevel`-style atomic level handle
  from `internal/logging`; detection dedup window via a setter on
  `detector.Engine`). Other keys return 400 `unsupported_field`. The YAML file
  on disk is **never** rewritten.
- `GET /api/whitelist`: lists `state.WhitelistEngine.ListWhitelist()`.
- `POST /api/whitelist` (admin): body `{mac, ssid?, comment?}` →
  `WhitelistEngine.AddWhitelist` + `repo.SaveWhitelistEntry`.
- `DELETE /api/whitelist/{mac}` (admin): remove from in-memory + storage.
- Same trio for `/api/blacklist`.

### Task 4.5 — SSE real-time channel
- `internal/api/sse.go`:
  ```go
  type Hub struct { ... }
  func NewHub(logger *slog.Logger) *Hub
  func (h *Hub) Publish(msg Message)
  func (h *Hub) Subscribe(ctx context.Context) <-chan Message
  func (h *Hub) Run(ctx context.Context)            // fan-out goroutine
  ```
- `Message` is `{ "type": "event"|"ap"|"client"|"status", "data": ... }`.
- The hub broadcasts to a sync.Map of subscriber channels with non-blocking
  send + drop-and-log when slow consumer.
- Wiring in `cmd/tobimaru/main.go`: replace single-consumer alerts goroutine
  with a fan-out — `consumeAlerts` (storage) and `hub.Publish(typeEvent, ev)`
  both subscribe to the same alerts stream. State updates: a small ticker in
  the hub (every 2 s) publishes diff snapshots from `state.Engine` (only if
  someone is subscribed, gated by `hub.HasSubscribers()`).
- `GET /api/stream` handler: sets `Content-Type: text/event-stream`, disables
  write timeout for the hijacked connection, sends `: ping\n\n` every 15 s,
  exits on `ctx.Done()` or client disconnect (`http.ResponseController.Flush`).

### Task 4.7 — SPA scaffolding & embedding
- Create `web/` with Vite (`npm create vite@latest`) using
  `react-ts` template. Add Tailwind, Recharts, React Router, a tiny fetch
  wrapper, and a small Zustand-or-Context store for auth/session state.
- `vite.config.ts`: `base: '/'`, `build.outDir: 'dist'`, dev proxy to
  `http://127.0.0.1:8080` for `/api` and `/api/stream`.
- `internal/api/web/embed.go`:
  ```go
  //go:embed all:dist
  var distFS embed.FS

  func Handler() http.Handler { ... }      // serves /assets, /favicon.ico
  func IndexHTML() ([]byte, error)         // for SPA fallback
  ```
  When `dist/index.html` is missing (Go-only build without `make web`), embed
  a placeholder that explains how to build the SPA — the binary still runs.
- The chi `NotFound` returns `IndexHTML()` for any non-`/api` GET so the SPA
  router handles client routes.

### Tasks 4.8–4.12 — Dashboard pages
- `Map.tsx` (4.8): table of APs with search/sort, expandable rows for clients,
  live-updates via SSE patches.
- `Events.tsx` (4.9): infinite-scroll list of events, filter bar (severity,
  type, time range), live-prepend on incoming SSE.
- `Stats.tsx` (4.10): bar chart `events_by_type`, line chart `events_per_hour`,
  pie chart `severity distribution`. Backed by `GET /api/stats` which runs
  SQL `SELECT event_type, severity, count(*) ...` aggregates with bucketed
  timestamps (hour buckets) and is cached for 30 s in handler memory.
- `Settings.tsx` (4.11): two tabs — "Configuration" (read-only YAML view + the
  three editable fields) and "Lists" (whitelist/blacklist tables with add/delete).
- `Status.tsx` (4.12): displays `/api/status` payload with capability badges
  and a live channel ticker driven by SSE.
- `Login.tsx`: simple form posting to `/api/login`. On 200, navigate to `/map`.
- `App.tsx`: routes; auth guard redirects to `/login` on 401 from any fetch.

### Wiring in `cmd/tobimaru/main.go`
After `pipeline.Start(signalCtx)` succeeds and detection/state are wired:
```go
if cfg.API.Enabled {
    hub := api.NewHub(logger)
    consumerWG.Go(func() { hub.Run(signalCtx) })

    // Alerts now fan out to storage AND hub.
    alertsCh := engine.Alerts()        // existing
    consumerWG.Go(func() {
        for ev := range alertsCh {
            hub.Publish(api.NewEventMessage(ev))
            // existing persistence / pruning logic from consumeAlerts moves
            // into a helper on the api.Server side or stays here unchanged.
        }
    })

    apiSrv, err := api.NewServer(cfg.API, api.Deps{
        State:        stateEngine,
        Repo:         repo,
        Pipeline:     pipeline,
        Detector:     engine,
        Config:       cfg,
        Hub:          hub,
        StartTime:    time.Now(),
        Logger:       logger,
    })
    if err != nil { /* fatal */ }

    consumerWG.Go(func() { _ = apiSrv.Run(signalCtx) })
    sm.Register("api_stop", func() error {
        ctx, cancel := context.WithTimeout(context.Background(), cfg.API.ShutdownTimeout)
        defer cancel()
        return apiSrv.Shutdown(ctx)
    })
}
```
The existing `consumeAlerts` is refactored to read from a forwarded channel
when the API is enabled, preserving its dedup-pruning behaviour.

### Build pipeline & CI
- `Makefile`:
  - `web-deps:` `cd web && npm ci`
  - `web:` `cd web && npm run build`
  - `build:` add a guard that checks for `web/dist/index.html` and warns
    (does not fail) if missing.
  - `lint-web:` runs `npm run lint` (eslint).
- `.github/workflows/ci.yml`: add a `setup-node@v4` step before existing Go
  steps, run `make web-deps web` so CI always rebuilds the bundle. The
  job artifact upload includes `web/dist/`. Lint job runs `make lint lint-web`.
- `.gitignore`: add `web/node_modules/`, `web/dist/.vite/`. **Do not** ignore
  `web/dist/` — built assets are committed.

### Spec updates
- `specs/architecture/layers.md`: add `internal/api → internal/{config,state,
  storage,detector,capture,version,parser}` (state DTOs only) under the
  hierarchy and dependency rules. Note `internal/api/web` as self-contained
  (only `embed`).
- `specs/contracts/main-internal.md`: append rows for
  `api.NewServer`, `api.Server.Run`, `api.Server.Shutdown`, `api.NewHub`,
  `api.Hub.Publish/Run`. Update startup-sequence and data-flow blocks.
- `specs/contracts/api-internal.md` (new): document each route, request/response
  schema, status codes, auth required, error envelope.
- `specs/domains/api.md` (new): describes the API domain — server lifecycle,
  middleware order, auth model, SSE hub semantics, embedded assets.
- `specs/decisions/005-chi-spa-sse.md` (new ADR): records the chi/SPA/SSE
  decisions and the trade-offs considered (stdlib mux, htmx, websocket).
- `specs/INDEX.md`: index the new domain/contract/ADR and the new task→spec rows.

### Tests
- `internal/api/server_test.go`: spin up server with `httptest.NewServer`
  backed by an in-memory SQLite repo; assert routing, auth required/rejected,
  admin-only enforcement on PUT/POST/DELETE.
- `handlers_*_test.go`: per-handler table-driven tests with fake state engine
  and seeded repo data.
- `sse_test.go`: subscribe N goroutines, publish, assert delivery order and
  slow-consumer drop. Race-tested.
- `auth_test.go`: bcrypt round-trip, token issuance, expired session rejection.
- `internal/storage/sqlite_test.go`: extend with sessions migration, CRUD,
  prune-expired test.
- `internal/config/config_test.go`: API defaults + validation for missing
  hash, invalid listen.
- `internal/api/web/embed_test.go`: verify embedded FS contains `index.html`
  and at least one asset.
- Coverage target: ≥ 70 % for `internal/api/`.

## Critical Files To Be Modified

| Path | Change |
|---|---|
| `cmd/tobimaru/main.go` | wire API server + SSE hub fan-out, add shutdown hook |
| `internal/config/config.go`, `defaults.go`, `validation.go` | new `APIConfig`, `AuthConfig`, `CORSConfig` + sentinel errors and defaults |
| `internal/storage/schema.go`, `sqlite.go`, `storage.go` | schema v2 sessions table + Session* methods on `Repository` |
| `internal/detector/detector.go` | add `SetDedupWindow(time.Duration)` setter (atomic), needed by PUT /api/config |
| `internal/logging/logging.go` | expose an `*slog.LevelVar` so `PUT /api/config` can change log level at runtime |
| `internal/capture/pipeline.go`, `channel.go` | expose `CurrentChannel() int` for `/api/status` |
| `configs/tobimaru.yaml` | sample `api:` block with comments |
| `Makefile` | `web`, `web-deps`, `lint-web` targets; soft check in `build` |
| `.github/workflows/ci.yml` | Node setup, `make web` step, lint-web step |
| `go.mod`, `go.sum` | add `github.com/go-chi/chi/v5`, `golang.org/x/crypto` |
| `.gitignore` | add `web/node_modules/`, keep `web/dist/` tracked |
| `specs/INDEX.md`, `specs/architecture/layers.md`, `specs/contracts/main-internal.md` | add API entries |

## Verification

1. **Static build & lint**
   - `make tidy && make fmt && make lint && make test` — Go side passes with
     race detector and ≥ 70 % coverage on `internal/api`.
   - `cd web && npm ci && npm run lint && npm run build` — SPA builds clean.

2. **Unit / handler tests**
   - `go test ./internal/api/... ./internal/storage/... ./internal/config/...`
     covers auth gates, CRUD endpoints, session migration, SSE fan-out.

3. **Local end-to-end smoke (macOS dev)**
   - Generate hashes: `go run ./cmd/tobimaru -hash-password admin` (small
     helper subcommand added under `-hash-password` flag — single function,
     reuse bcrypt) → put values into `configs/tobimaru.yaml`.
   - `make build && ./bin/tobimaru -config configs/tobimaru.yaml` (storage
     enabled, monitor on `en0` or a stub interface).
   - `curl -i http://127.0.0.1:8080/api/status` → 200 with capabilities JSON.
   - `curl -i -c jar -X POST -d '{"username":"admin","password":"..."}' \
     http://127.0.0.1:8080/api/login` → 200 + Set-Cookie.
   - `curl -b jar http://127.0.0.1:8080/api/aps` → 200 with AP list.
   - `curl -b jar -N http://127.0.0.1:8080/api/stream` → receives keepalives
     and any generated event within 1 s of detection.
   - `curl -b jar -X POST -H 'Content-Type: application/json' \
     -d '{"mac":"aa:bb:cc:dd:ee:ff","comment":"test"}' \
     http://127.0.0.1:8080/api/whitelist` → 201; restart binary; entry persists.
   - Open `http://127.0.0.1:8080/` → login page → after auth, navigate Map /
     Events / Stats / Settings / Status pages and confirm live updates.

4. **Cross-platform build**
   - `make build-all` — Linux amd64/arm64 + Darwin arm64 binaries embed the
     same `web/dist/` and run.

5. **Spec consistency**
   - Run the `vibespec-check` skill (or manually) to confirm
     `specs/architecture/layers.md`, `specs/contracts/*`, `specs/INDEX.md`
     reflect the new `internal/api` package and the new ADR is indexed.

6. **Definition of Done audit (roadmap §Phase 4)**
   - All 12 documented endpoints respond correctly ✔
   - Real-time channel delivers events within 1 s ✔ (SSE keepalive 15 s,
     publishes are immediate)
   - Dashboard renders environment map, events feed, statistics, settings ✔
   - User/admin role separation enforced ✔
   - Single-binary deployment (assets embedded) ✔
   - Works in Chrome, Firefox, Safari (Vite produces ES2020+ bundles) ✔
