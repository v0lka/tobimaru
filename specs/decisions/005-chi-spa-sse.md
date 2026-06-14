# ADR-005: chi router, React SPA, SSE for real-time updates

## Status

Accepted

## Context

Phase 4 of the project (`docs/development/wifi-watchdog-roadmap.md`) requires
exposing captured/detected data through a REST API and providing an embedded
web dashboard. Three orthogonal technology choices were on the table:

1. HTTP routing — `net/http.ServeMux` (Go 1.22+) versus a third-party router.
2. Web framework — vanilla HTML/JS, server-rendered Go templates with HTMX,
   or a pre-built single-page application.
3. Real-time updates — Server-Sent Events versus WebSockets.

The dashboard needs five pages (Map, Events, Stats, Settings, Status), live
updates within 1 s of detection, role-based auth, and single-binary
deployment. The project's ethos is Go-first with minimal dependencies, but
the dashboard targets browser users who expect a modern UX.

## Decision

- **Router**: `github.com/go-chi/chi/v5`. Idiomatic, tiny (~10 KB), supports
  sub-routers and per-group middleware, which keeps the auth boundary
  explicit (`r.Group(requireAuth)` and `r.Group(requireAdmin)`).
- **Web framework**: React 19 + Vite + TypeScript SPA, built into
  `internal/api/web/dist/` and embedded with `go:embed all:dist`. The build
  output is committed to git so contributors who only work on Go can produce
  a binary without Node. CI (`make web`) refreshes the bundle.
- **Real-time**: Server-Sent Events via `GET /api/stream`. The stream is
  one-way (server → client) which fits the use case (event push + state
  diffs); browsers handle reconnection natively; no extra dependency.

## Consequences

Positive:
- Small, predictable Go dependency surface (`chi/v5`, `golang.org/x/crypto`).
- Modern dashboard DX: typed TS, hot reload via `npm run dev` with a Vite
  proxy to `127.0.0.1:8080`.
- SSE works through TLS-terminating proxies and HTTP/2 without WebSocket
  upgrade negotiation.
- Single binary deployment: `make build` produces a self-contained binary
  with the dashboard embedded.

Negative:
- Two toolchains in CI (Go + Node 22). Mitigated by running them as
  independent jobs and by committing `web/dist/` so Go builds work without
  Node.
- The committed bundle adds ~200 KB to the repository per refresh.
- SSE is one-way — if a future feature needs client-to-server pushes (for
  example interactive frame injection commands), it has to use POSTs or be
  upgraded to WebSocket.

## Alternatives Considered

- **Stdlib `http.ServeMux`**. Rejected: usable but middleware composition is
  cumbersome and per-group auth requires manual boilerplate.
- **HTMX + html/template**. Rejected: ties pages to Go templates, complicates
  charts (Stats page) and live updates, and the user explicitly chose a SPA.
- **WebSocket (gorilla/websocket)**. Rejected: full-duplex is unnecessary;
  the SPA never pushes telemetry back. SSE delivers the requirement with
  less code.
- **All-interfaces default bind**. Rejected: would expose the dashboard on
  every NIC at first run; loopback default with optional reverse proxy is
  safer.
- **TLS in process**. Rejected for Phase 4: cert management is out of scope;
  operators put the daemon behind nginx/caddy when remote access is needed.

## Related

- [Domain: API & Web Dashboard](../domains/api.md)
- [Contract: API ↔ Internal](../contracts/api-internal.md)
- [Contract: Main ↔ Internal](../contracts/main-internal.md)
