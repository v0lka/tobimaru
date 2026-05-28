# ADR-001: YAML Configuration with KnownFields Strict Parsing

## Status

Accepted

## Context

The application needs a configuration format that is:
- Human-readable and editable by end users configuring WiFi monitoring
- Self-documenting through comments and clear structure
- Resistant to typos and misconfigurations (critical for a security daemon)
- Parsed into strongly-typed Go structs without boilerplate

Go ecosystem options: YAML (`gopkg.in/yaml.v3`), TOML (`BurntSushi/toml`), JSON (stdlib), HCL (HashiCorp).

## Decision

Use **YAML** (`gopkg.in/yaml.v3`) with `KnownFields(true)` strict parsing enabled.

`KnownFields(true)` causes the YAML decoder to return an error if the config file contains keys that don't match any struct field — preventing silent ignoring of typos like `monitor.interfce` or `log.level: inf`.

Defaults are applied via `applyDefaults()` post-parse, and validation runs via `validate()` before returning — guaranteeing all consumers receive a fully-initialized, validated `*Config`.

## Consequences

**Positive:**
- User-friendly format with comments (unlike JSON)
- Typo detection at startup prevents misconfigured daemon from running silently
- Strongly-typed Go structs — no map-based or dynamic access needed
- `yaml.v3` is stable, well-maintained, and widely used in Go projects
- `KnownFields(true)` catches config drift before it causes runtime bugs

**Negative:**
- YAML requires adding a dependency (`gopkg.in/yaml.v3`) — though clean and minimal
- Strict parsing means adding a new config field requires updating the struct BEFORE users can set it — forward-compatibility requires explicit migration
- YAML's indentation sensitivity can confuse users unfamiliar with the format

## Alternatives Considered

| Alternative | Rejection Reason |
|-------------|-----------------|
| **TOML** | Less familiar to many users; narrower ecosystem. No strict-key equivalent to `KnownFields`. |
| **JSON** | No comment support — unacceptable for user-facing config. Verbose syntax. |
| **HCL** | Overkill for a single-daemon config; heavy dependency. Designed for Terraform-like nested block structures. |
| **YAML without `KnownFields`** | Silently ignores typos — unacceptable for a security daemon that must not run with unintended config. |
| **Environment variables** | Good for 12-factor apps but poor UX for complex nested WiFi monitoring config (channel lists, dwell times, etc.) |
| **`github.com/goccy/go-yaml`** | Faster but less stable API; `yaml.v3` is sufficient for config loading (not a hot path). |
