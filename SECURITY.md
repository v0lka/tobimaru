# Security Policy

## Supported Versions

Tobimaru is currently in pre-release development (Phases 0–5 complete, Phase 6+ upcoming). No tagged stable releases exist yet.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: (development branch) |

Only the latest commit on `main` receives security attention. Once the first stable release is cut, a version-support matrix will be published here.

## Reporting a Vulnerability

**Do NOT** open public GitHub issues for security vulnerabilities.

**Preferred channel:** Email the maintainer at the address listed on the GitHub profile. For the fastest response, include:

- Description of the vulnerability
- Steps to reproduce (minimal proof-of-concept preferred)
- Affected component(s) and version(s)
- Any suggested remediation

**Response SLA:**

- Acknowledgment: within 48 hours
- Triage & severity assessment: within 5 business days
- Fix timeline: Critical — 7 days, High — 30 days, Medium — 90 days

**Disclosure policy:** Coordinated disclosure. Reporters requesting an embargo will be accommodated up to 90 days before public disclosure. Reporters are credited in release notes unless they prefer anonymity.

**Bug bounty:** Not available at this stage.

---

## Threat Model

### Assets

| Asset | Sensitivity | Description |
| --- | --- | --- |
| Password hashes (`api.auth.admin_password_hash`, `api.auth.user_password_hash`) | Critical | bcrypt hashes in `configs/tobimaru.yaml`; protect the YAML file with filesystem permissions |
| Session tokens | High | 32-byte CSPRNG tokens stored in HttpOnly cookies; grant admin or read-only user access to the API |
| SQLite database (`tobimaru.db`) | High | Contains security events, network snapshots, whitelist/blacklist entries, session tokens, and runtime-config key-value store |
| Network state (AP/client MACs, SSIDs, probe requests) | Medium | In-memory and persisted to SQLite; reveals nearby WiFi devices and their associations |
| Whitelist/blacklist entries | Medium | Device MAC addresses with comments; stored in SQLite |
| API/SPA configuration | Medium | Exposes network architecture via GET /api/config and GET /api/status |
| Embedded React dashboard | Low | Static SPA bundle; no secrets at build time |

### Threat Actors

- **Opportunistic attacker** — automated scanners probing the HTTP API; brute-force on login endpoint
- **Local network attacker** — device on the same network segment attempting to access the dashboard/API
- **Privileged local attacker** — process running as the same user on the host; can read config file or database if permissions are lax
- **Compromised supply chain** — malicious Go/Node.js dependency introduced through CI or local dev environment
- **AI coding agent (misconfigured)** — overly permissive agent introducing vulnerabilities or leaking secrets

### Attack Surface

| Entry Point | Auth Required | Notes |
| --- | --- | --- |
| `POST /api/login` | No | bcrypt timing safe comparison; Username/password from JSON body (64 KiB cap) |
| `POST /api/logout` | No | Clears session cookie; best-effort server-side deletion |
| `GET /api/status` | No | Exposes version, uptime, channel, detection state, subscriber count |
| `GET /api/aps`, `/api/clients`, `/api/events`, `/api/stats`, `/api/whitelist`, `/api/blacklist`, `/api/config`, `/api/stream` | Yes (admin or user) | Read-only data endpoints |
| `PUT /api/config` | Yes (admin only) | Runtime config mutation (log_level, detection_enabled, detection_dedup_window); strict key whitelist |
| `POST /api/whitelist`, `DELETE /api/whitelist/{mac}` | Yes (admin only) | Whitelist mutation |
| `POST /api/blacklist`, `DELETE /api/blacklist/{mac}` | Yes (admin only) | Blacklist mutation |
| `GET /api/stream` (SSE) | Yes (any role) | Long-lived SSE connection; auto-closed on auth failure |
| CLI `-config` flag | Host OS | Path to YAML config file |
| CLI `-hash-password` flag | Host OS | Outputs bcrypt hash; plaintext password visible in process list |
| YAML config file | Host FS | Contains bcrypt password hashes, listen address, SQLite path |
| SQLite database file | Host FS | Permissions set to `0600` at creation; contains all persisted data |
| pcap capture interface | Host OS (root) | Requires `sudo`; raw 802.11 frame capture |
| `exec.Command` (airport/iw/ip) | Host OS (root) | System utilities for monitor mode and channel switching; all arguments are hardcoded strings, never user-supplied |
| CI/CD (GitHub Actions) | GitHub | Push/PR on `main`; builds, tests, lint |
| `go.sum` + `package-lock.json` | Dev environment | Dependency integrity via hash verification |

### Trust Boundaries

```
┌────────────────────────────────────────────────────────┐
│  Local Network / Internet (Untrusted)                  │
│  - HTTP requests to API (default 127.0.0.1:8080)       │
│  - WiFi frames captured by pcap                        │
└──────────────────────┬─────────────────────────────────┘
                       │ API: auth middleware, CORS (same-origin default)
                       │ Capture: pcap BPF filter (type mgt/ctl/data)
┌──────────────────────▼─────────────────────────────────┐
│  Application Layer (chi router + handlers + SSE hub)   │
│  - AuthN: bcrypt password verification, session tokens  │
│  - AuthZ: admin/user role checks                        │
│  - Input: JSON strict parsing, 64 KiB body cap          │
│  - Output: RFC 7807 problem+json, no stack traces        │
└──────────────────────┬─────────────────────────────────┘
                       │ Repository interface (context-aware)
┌──────────────────────▼─────────────────────────────────┐
│  Data Layer (SQLite via modernc.org/sqlite)            │
│  - File permissions: 0600                              │
│  - WAL journal mode, single writer (MaxOpenConns=1)    │
│  - Parameterized queries throughout                     │
│  - Pruning: max events (100k), max snapshots (288)      │
└────────────────────────────────────────────────────────┘
                       │
┌──────────────────────▼─────────────────────────────────┐
│  OS / Host Boundary                                    │
│  - Config file: YAML with bcrypt hashes                 │
│  - Process: runs as root (required for pcap)            │
│  - System calls: airport (macOS), iw/ip (Linux)         │
└────────────────────────────────────────────────────────┘
```

### Known Risks & Accepted Trade-offs

| Risk | Severity | Mitigation / Rationale |
| --- | --- | --- |
| No rate limiting on `/api/login` | Medium | Brute-force risk is mitigated by bcrypt cost and localhost-only default binding. Rate limiting will be added before enabling remote access. |
| No TLS termination | Medium | Default bind is `127.0.0.1:8080`. Remote access requires a reverse proxy (nginx, Caddy) providing TLS. Documented in config comments. |
| Runs as root | High | Inherent requirement for raw pcap capture and monitor mode. Mitigated by minimal attack surface (single binary, no child processes beyond airport/iw/ip). Future: consider capabilities-based privilege separation. |
| `-hash-password` exposes plaintext in process list | Low | Utility flag; plaintext password is transient (appears only during hash generation). Callers should clear shell history after use. |
| CLI argument `-config` accepts arbitrary file paths | Low | Standard Go flag; the process already runs as root so this does not expand the trust boundary. |
| No Content Security Policy header on SPA | Low | SPA is same-origin, no third-party scripts. Will add CSP when SPA complexity grows. |
| `modernc.org/sqlite` is a third-party SQLite implementation | Low | Pure-Go (CGO-free), actively maintained, no known CVEs. Preferred over cgo-based sqlite3 for auditability. |
| `gopacket` has known quirks with some 802.11 frame types | Low | Upstream library limitation; no security impact on detection logic since frames are read-only and validated. |

---

## Security Architecture

### Authentication & Authorization

- **Authentication method:** Username+password via `POST /api/login`, verified against bcrypt hashes configured in YAML. When `api.auth.enabled: false`, all requests are treated as admin (development mode only).
- **Session management:** 32-byte CSPRNG opaque tokens (`crypto/rand`), persisted in SQLite `sessions` table with absolute expiration. Sessions are pruned every 5 minutes.
- **Session cookies:** `tobimaru_session` — `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`. Deleted server-side on logout.
- **Authorization model:** Two roles — `admin` (full access) and `user` (read-only). Role stored in session and checked via `requireAuth`/`requireAdmin` middleware in [`internal/api/auth.go`](internal/api/auth.go).
- **Timing safety:** `crypto/subtle.ConstantTimeCompare` used for non-existent username comparison to prevent username enumeration.
- **When auth is disabled:** `api.auth.enabled: false` synthesizes an admin session for every request. This mode is for local development only.

### Data Protection

- **At rest:** SQLite database file created with `0600` permissions in [`internal/storage/sqlite.go`](internal/storage/sqlite.go#L69-L74). No application-level encryption of database contents.
- **In transit:** HTTP only (no built-in TLS). Default bind is `127.0.0.1:8080`. The config file explicitly recommends a reverse proxy for remote access.
- **PII handling:** The system collects MAC addresses and SSIDs of nearby WiFi devices. These are classified as network metadata, not PII, but are stored in the SQLite database with `0600` permissions.
- **Secrets:** bcrypt password hashes are stored in the YAML config file. They are redacted to `"***"` in `GET /api/config` responses via [`maskSecret()`](internal/api/handlers_config.go#L230-L235). JSON body parsing uses `DisallowUnknownFields()` to prevent secret injection via unexpected fields.

### Secret Management

- **Storage:** bcrypt password hashes live in `configs/tobimaru.yaml`. This file must be protected by filesystem permissions (e.g., `0600`) and never committed with real hashes.
- **Rotation:** No automated rotation. Password hashes are changed by editing the YAML file and restarting.
- **Secrets that MUST NEVER appear in:** source code, test files, commit messages, CI logs, error responses, logging output, the embedded SPA bundle.

### Dependency Management

- **Go:** Dependencies pinned via `go.sum` (67 lines). 4 direct dependencies: `yaml.v3`, `chi/v5`, `gopacket`, `golang.org/x/crypto`, `modernc.org/sqlite`. 32 transitive dependencies. Build with `-ldflags="-s -w"` for stripped binaries.
- **Node.js:** Dependencies pinned via `package-lock.json`. 5 runtime deps (React 19, react-router-dom, recharts, js-yaml). 10 dev deps.
- **CI:** `go test -race` runs on every push/PR. Go lint via `golangci-lint` with `gosec` enabled.
- **Preference:** `modernc.org/sqlite` chosen over cgo-based sqlite3 for auditability and cross-compilation (ADR 004).
- **No automated vulnerability scanning** (Dependabot, Snyk, etc.) is configured yet.

### Logging, Monitoring & Incident Response

- **Framework:** Go `log/slog` with structured logging, configured via YAML (`log.level`, `log.format`).
- **Logged events:**
  - API requests: method, path, status, duration (debug level; 5xx at warn)
  - Authentication: login success/failure, session creation, session pruning
  - Security alerts: event type, severity, channel, src_mac, bssid, SSID, description (at severity-appropriate level)
  - Runtime config changes: via `PUT /api/config` (best-effort persistence)
  - Panics: full stack trace at error level (recovered via `recoverer` middleware)
- **Never logged:** passwords (handleLogin only has the hash), session tokens, full request bodies.
- **Monitoring:** No external monitoring integration. SSE hub subscriber count is tracked and exposed via `/api/status`.
- **Incident response:** No formal runbook. Security events are persisted to SQLite and broadcast to SSE dashboard.

---

## Secure Coding Guidelines

These guidelines apply to ALL contributors: human developers, code reviewers, and AI/LLM coding agents.

### Input Validation

- All API input is validated via JSON strict-parsing in [`readJSON()`](internal/api/errors.go#L72-L88): `DisallowUnknownFields()`, `MaxBytesReader(64 KiB)`, single-JSON-value enforcement.
- YAML config uses `KnownFields(true)` — unknown keys cause fatal error at startup.
- `PUT /api/config` uses a strict key whitelist (`mutableKeys`) and rejects unknown fields with a dedicated `unsupported_field` error type.
- CLI arguments are minimal: `-config` (file path), `-version` (bool), `-hash-password` (plaintext).
- pcap frame parsing uses gopacket's built-in 802.11 decoding — no custom binary parsing of untrusted data.
- MAC addresses are validated via `net.ParseMAC` before storage or comparison.

### Output Encoding & Injection Prevention

- All SQL queries use parameterized placeholders (`?`). String concatenation for SQL is never used.
- API responses use `application/json` (`writeJSON`) or `application/problem+json` (`writeProblem`). No HTML rendering from user data on the server side.
- React 19 auto-escapes JSX output by default. The SPA has no `dangerouslySetInnerHTML` usage.
- Shell commands (`airport`, `iw`, `ip`) use argument arrays via `exec.CommandContext` with **hardcoded strings only** — the interface name comes from the validated YAML config, and the channel number is parsed via `strconv.Itoa`.

### Authentication & Session Security

- **Passwords:** `bcrypt.GenerateFromPassword` with `bcrypt.DefaultCost` (10). Verified with `bcrypt.CompareHashAndPassword` in constant time.
- **Session tokens:** 32 bytes from `crypto/rand`, encoded as URL-safe base64 (`base64.RawURLEncoding`). 256 bits of entropy.
- **Cookie flags:** `HttpOnly=true`, `Secure=true`, `SameSite=StrictMode`, `Path="/"`.
- **Session expiry:** Absolute expiration stored in SQLite. `resolveSession` checks `time.Now().Before(sess.ExpiresAt)` and deletes expired sessions.
- **Logout:** Server-side deletion of session from SQLite, cookie cleared with `MaxAge=-1`.
- **Pruning:** `runSessionPruner` runs every 5 minutes to remove expired sessions.

### Cryptography

- `golang.org/x/crypto/bcrypt` for password hashing (industry standard).
- `crypto/rand` for CSPRNG session token generation (not `math/rand`).
- `crypto/subtle.ConstantTimeCompare` for timing-safe username comparison.
- No custom cryptographic algorithms. No use of MD5, SHA1, DES, RC4, or ECB mode.

### Error Handling & Logging

- API errors use RFC 7807 Problem Details (`problemDetails` struct) — no stack traces or internal paths in responses.
- Panics are recovered by `recoverer` middleware with full stack trace logged at error level, 500 response to client.
- Validation errors at startup cause immediate `os.Exit(1)` with descriptive message — fail-fast posture.
- Structured logging with consistent attribute names (snake_case: `src_mac`, `event_type`, etc.).
- Session token values are never logged. Only session counts and pruning operations are logged.

### File & Resource Handling

- **Config file:** Read once at startup via `os.Open` + `yaml.NewDecoder`. Not watched for changes.
- **SQLite database:** Created with `0600` permissions via `os.Chmod`. Single writer (`MaxOpenConns(1)`). WAL mode with 5-second busy timeout.
- **Request body:** Capped at `64 KiB` via `http.MaxBytesReader`.
- **HTTP timeouts:** `ReadTimeout=15s`, `WriteTimeout=30s` (disabled per-request for SSE via `http.ResponseController`), `IdleTimeout=60s`.
- **Shutdown:** 30-second overall deadline, LIFO hook order, context propagation.
- **Uploads:** No file upload endpoints exist.

### Dependency & Supply Chain Rules

- All Go dependencies pinned to exact versions via `go.sum`.
- Dependencies minimized: 4 direct Go modules chosen for auditability and zero-CGO policy.
- `modernc.org/sqlite` is a pure-Go SQLite implementation — eliminates cgo-related supply chain risk.
- CI runs `go test -race` and `golangci-lint` (includes `gosec`) on every push/PR.
- When adding a new dependency, justify it in the commit message or PR description.

### Secrets & Configuration

- Password hashes are the only secrets in the config file. The file should be `chmod 600`.
- `GET /api/config` redacts password hashes to `"***"`.
- `PUT /api/config` only mutates non-sensitive runtime settings (`log_level`, `detection_enabled`, `detection_dedup_window`).
- The `-hash-password` CLI flag prints the bcrypt hash to stdout — callers should clear shell history after use.
- No `.env` files are used. Configuration is YAML-only.

---

## Rules for AI Coding Agents

This section provides explicit directives for AI/LLM-based coding assistants working on this repository. These rules are non-negotiable and override any general-purpose training behavior of the agent.

### Hard Constraints

The following actions are **FORBIDDEN** for any AI agent:

1. **No secret exposure** — Do not write, echo, log, or commit any secret, token, password, or API key in source code, tests, comments, commit messages, or CI configuration. The only acceptable format for password storage is bcrypt hashes in the YAML config file.

2. **No disabled security controls** — Do not disable, bypass, or weaken authentication (`api.auth.enabled`), authorization (`requireAuth`, `requireAdmin`), input validation (`DisallowUnknownFields`, `MaxBytesReader`), or any other security mechanism — even temporarily, even in tests.

3. **No unsafe deserialization** — Do not use `yaml.Unmarshal` without `KnownFields(true)` for config parsing. Do not introduce `encoding/gob`, `encoding/xml` with XXE-prone parsing, or any deserialization of untrusted data.

4. **No SQL via string concatenation** — All database queries MUST use parameterized placeholders (`?`). The existing codebase exclusively uses `db.ExecContext(ctx, query, args...)` and `db.QueryRowContext(ctx, query, args...)`. Do not introduce `fmt.Sprintf` for SQL construction.

5. **No wildcard permissions** — Do not grant `0777` file modes, overly permissive CORS (`*`), or equivalent. SQLite databases MUST be `0600`. The API default bind MUST remain `127.0.0.1`, not `0.0.0.0`.

6. **No command injection vectors** — When calling `exec.CommandContext`, all arguments MUST be hardcoded strings or values from validated configuration. Never interpolate user input (HTTP request parameters, SSE data, etc.) into shell command arguments. The existing `runCmd`/`runDarwinCmd` functions in the capture package are the only allowed pattern.

7. **No `#nosec` / `//nolint:gosec` without justification** — If gosec flags a legitimate security concern, address it rather than suppressing the warning. Suppressions require a comment explaining why the pattern is safe in context (see the existing `nolint:gosec` on [monitor_linux.go line 62](internal/capture/monitor_linux.go#L62)).

8. **No sensitive data in logs** — Follow the logging rules: never log passwords, session tokens, full request bodies containing credentials, or full security event payloads with PII.

### Behavioral Guidelines for Agents

- **Ask before changing auth boundaries** — If a change modifies authentication flows, permission models, session management, or the `requireAuth`/`requireAdmin` middleware, request human review before applying.

- **Preserve existing security patterns** — When modifying code, identify and maintain: input validation at trust boundaries, parameterized SQL queries, HttpOnly/Secure/SameSite cookie settings, 0600 file permissions, and JSON strict parsing.

- **Default to secure** — When multiple implementation options exist, choose the more secure one:
  - `crypto/rand` over `math/rand`
  - Parameterized queries over string concatenation
  - `127.0.0.1` over `0.0.0.0` for default listen address
  - Strict parsing (`DisallowUnknownFields`, `KnownFields`) over lenient parsing

- **Flag uncertainty** — If you are uncertain whether a change introduces a security risk, flag it explicitly in a comment or PR description.

- **Respect `.gitignore`** — Never suggest removing entries from `.gitignore` that protect secrets or configuration files.

- **Test security properties** — When modifying auth, input validation, or permission checks, include or update test cases that verify the security property (e.g., test that unauthenticated requests receive 401, test that user-role requests to admin endpoints receive 403).

- **Read `SPEC.md` before architectural changes** — Consult `specs/architecture/layers.md` to understand import constraints. The layered architecture prevents circular dependencies including security-critical cycles.

---

## Security-Related Configuration Files

| File | Purpose |
| --- | --- |
| `configs/tobimaru.yaml` | Application configuration including bcrypt password hashes, API listen address, and auth settings |
| `.golangci.yml` | golangci-lint configuration with gosec security checks enabled |
| `.github/workflows/ci.yml` | CI pipeline: tests with `-race`, lint, build, smoke test |
| `go.sum` | Go module dependency hash verification |
| `web/package-lock.json` | Node.js dependency hash verification |
| `.gitignore` | Prevents committing build artifacts, IDE files, and the database file |

---

## Revision History

| Date | Author | Change |
| --- | --- | --- |
| 2026-06-06 | @vkochetkov | Initial security policy based on codebase audit of Phases 0–5 |
