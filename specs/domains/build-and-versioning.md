# Build & Versioning

## Purpose

Provides build-time version injection, cross-compilation targets, linting configuration, and a CI pipeline that runs on every push and pull request.

## Key Files

- `internal/version/version.go` — `Version`, `Commit`, `Date` variables + `String()` formatter
- `internal/version/version_test.go` — unit tests for version string formatting
- `Makefile` — build orchestration: `all`, `build`, `build-all`, `test`, `lint`, `run`, `clean`
- `.golangci.yml` — lint configuration (golangci-lint v2)
- `.github/workflows/ci.yml` — CI pipeline: lint, test (with race detector), build matrix
- `go.mod` — module definition and dependency declarations

## Core Types

```go
// internal/version/version.go
var (
    Version = "dev"       // injected via ldflags: -X .../version.Version=$VERSION
    Commit  = "unknown"   // injected via ldflags: -X .../version.Commit=$COMMIT
    Date    = "unknown"   // injected via ldflags: -X .../version.Date=$DATE
)

func SetVersion(v, c, d string)  // test-only helper to set build info (not concurrent-safe)
func String() string              // "Tobimaru v{VERSION} (commit: {COMMIT}, built: {DATE})"
```

## Flow

### Build (via Makefile)

```
make build
  │
  ├─► Compute variables:
  │     VERSION ?= dev
  │     COMMIT  ?= $(git rev-parse --short HEAD)
  │     DATE    ?= $(date -u +"%Y-%m-%dT%H:%M:%SZ")
  │
  └─► go build -ldflags "-s -w
        -X github.com/vkochetkov/tobimaru/internal/version.Version=$(VERSION)
        -X github.com/vkochetkov/tobimaru/internal/version.Commit=$(COMMIT)
        -X github.com/vkochetkov/tobimaru/internal/version.Date=$(DATE)"
        -o bin/tobimaru ./cmd/tobimaru
```

### Cross-compilation (`make build-all`)

```
make build-all
  │
  ├─► GOOS=linux   GOARCH=amd64  → bin/tobimaru-linux-amd64
  ├─► GOOS=linux   GOARCH=arm64  → bin/tobimaru-linux-arm64
  └─► GOOS=darwin  GOARCH=arm64  → bin/tobimaru-darwin-arm64
```

### CI pipeline

```
Push/PR to main
  │
  ├─► Job: lint
  │     ├─ Setup Go 1.26
  │     ├─ Install libpcap-dev
  │     └─ golangci-lint run ./...
  │
  ├─► Job: web (Vite build)
  │     ├─ Setup Node 22
  │     ├─ Install SPA dependencies
  │     ├─ Build SPA + lint
  │     └─ Upload built web/dist artifact
  │
  ├─► Job: test (Linux)
  │     ├─ Setup Go 1.26
  │     ├─ Install libpcap-dev
  │     ├─ go test -race -cover -coverprofile=coverage.out ./...
  │     └─ Upload coverage to Codecov
  │
  ├─► Job: build (matrix: 3 platforms)
  │     ├─ Setup Go 1.26
  │     ├─ go build with ldflags for each GOOS/GOARCH
  │     └─ Upload binary as artifact
  │
  └─► Job: test (macOS)
        ├─ Setup Go 1.26
        ├─ go test -race -cover -coverprofile=coverage-macos.out ./...
        ├─ go build -o tobimaru-macos ./cmd/tobimaru
        ├─ Smoke test: ./tobimaru-macos --version
        └─ Upload coverage to Codecov
```

### Version display

```
./bin/tobimaru --version
    → "Tobimaru vdev (commit: 70f3cae, built: 2026-05-27T19:34:59Z)"
```

The `--version` flag is parsed in `cmd/tobimaru/main.go` and prints `version.String()`, then exits before any config loading or component initialization.

## Invariants

- `Version`, `Commit`, and `Date` are always overwritten at build time via ldflags — their default values (`"dev"`, `"unknown"`, `"unknown"`) are only seen in `go run`
- `-s -w` ldflags strip debug symbols and DWARF — reduces binary size for distribution
- CI tests with Go 1.26, matching the `go.mod` declaration of `go 1.26.3`
- Cross-compilation requires CGO (due to `gopacket/pcap` dependency on libpcap) — the CI installs `libpcap-dev` on Linux runners
- `golangci-lint` uses v2 configuration format with ~41 enabled linters + 2 formatters
- Every push and PR to `main` triggers the full CI pipeline

## Configuration

### Makefile variables

| Variable | Default | Override | Purpose |
|----------|---------|----------|---------|
| `VERSION` | `dev` | `VERSION=1.0.0 make build` | Version string in binary |
| `COMMIT` | `$(git rev-parse --short HEAD)` | `COMMIT=custom make build` | Git commit hash |
| `DATE` | `$(date -u +"%Y-%m-%dT%H:%M:%SZ")` | `DATE=custom make build` | Build timestamp |
| `BINARY_NAME` | `tobimaru` | — | Binary output name |
| `BUILD_DIR` | `bin` | — | Output directory |
| `GOOS` | `$(shell go env GOOS)` | `GOOS=linux` | Target OS |
| `GOARCH` | `$(shell go env GOARCH)` | `GOARCH=arm64` | Target architecture |

### Makefile targets

| Target | Description |
|--------|-------------|
| `all` | Restore all deps (Go + npm), build web, then build binary |
| `build` | Build binary for current platform |
| `build-all` | Cross-compile for all 3 targets |
| `test` | Run tests with race detector and coverage |
| `test-cover` | Run tests and open coverage report in browser |
| `lint` | Run golangci-lint |
| `run` | Build and run with ldflags |
| `clean` | Remove build artifacts |
| `web-deps` | Install SPA build dependencies (npm ci) |
| `web` | Sync logo from `images/`, then build the SPA into `internal/api/web/dist/` |
| `web-clean` | Remove the embedded SPA bundle |
| `lint-web` | Lint SPA sources with ESLint |
| `fmt` | Format all Go source files |
| `tidy` | Tidy Go modules |
| `help` | Show all targets with descriptions |

## Extension Points

- **Adding a new target platform:** add a line to `build-all` in the `Makefile` and a matrix entry in `.github/workflows/ci.yml`
- **Adding a new ldflag variable:** add a `var` to `internal/version/version.go`, a build variable to the `Makefile`, and the `-X` flag
- **Adding a CI job:** add a new job to `.github/workflows/ci.yml` (e.g., integration tests, container build)
- **Changing lint rules:** edit `.golangci.yml` — `linters.enable`, `linters.settings`, `linters.exclusions`

## Related Specs

- [ADR-002: ldflags Version Injection](../decisions/002-ldflags-version.md) — why ldflags over compile-time codegen
