# ADR-002: ldflags Version Injection

## Status

Accepted

## Context

The project needs version, commit hash, and build date metadata embedded in the binary. This enables:
- Verifying which version is deployed when debugging production issues
- CI pipeline artifact traceability
- `--version` flag output for user diagnostics

Go offers two approaches: compile-time code generation (`go generate` + a codegen script) or linker flag injection (`-ldflags -X`).

## Decision

Use **ldflags injection** via `-X` linker flags in `Makefile` and CI pipeline.

Variables injected at build time:
```
-X github.com/vkochetkov/tobimaru/internal/version.Version=$VERSION
-X github.com/vkochetkov/tobimaru/internal/version.Commit=$COMMIT
-X github.com/vkochetkov/tobimaru/internal/version.Date=$DATE
```

The `internal/version` package defines these as mutable `var` declarations with default `"dev"`/`"unknown"` values for development (`go run` without ldflags).

## Consequences

**Positive:**
- Zero extra files — no generated code to commit or maintain
- Works natively with `Makefile` variables and CI environment variables
- Simple `--version` flag integration: `fmt.Println(version.String())`
- No build-time dependency on `git` or `date` — falls back to `"unknown"` gracefully
- ldflags `-s -w` also strips debug symbols, reducing binary size

**Negative:**
- `go run` always shows `"dev"`/`"unknown"` — developers must remember to use `make run` for real versions
- ldflags format is verbose: full package path + variable name
- Not discoverable through IDE autocompletion (unlike codegen approaches)
- Version variables are mutable at the package level — could be accidentally overwritten at runtime (mitigated by not exporting setters)

## Alternatives Considered

| Alternative | Rejection Reason |
|-------------|-----------------|
| **`go generate` + codegen** | Generates a file (`version_gen.go`) that must be committed or regenerated. Creates a chicken-and-egg problem: generated file must exist for `go build`, but git info may not be available. Requires a bash/Python script in the repo. |
| **`runtime/debug.ReadBuildInfo()`** | Only available for modules built with `go install`, not `go build`. Injects VCS info but not arbitrary version strings or build dates. Less control. |
| **`embed` a VERSION file** | Requires maintaining a separate file. Doesn't capture commit hash or build date without extra tooling. |
| **`runtime.BuildInfo` with `go build -buildvcs=true`** | Go 1.18+ embeds VCS info, but only for modules fetched from VCS. Local `go build` produces partial info. No control over version string. |
