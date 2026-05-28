# Specification Workflow

A reference guide for developers and AI agents on effective use of this project's specification system.

---

## 1. General Philosophy

Specifications are the **source of truth** about the intended behavior of the system. They are not generated from code; they are maintained manually. Key implications:

- A discrepancy between a spec and the code = a bug (in the code or in the spec — determine by context).
- Specs are optimized for **AI agents**: predictable structure, explicit cross-references, no filler prose.
- Organized by **domains** (conceptual areas), NOT by repository file structure.
- **Contracts** are a separate first-class entity for describing boundaries between layers.

---

## 2. Getting Started: Navigation

### Step 1: INDEX.md

Open `specs/INDEX.md`. It contains a "task → specs" table that maps common tasks to the spec files you should read.

### Step 2: Domain Spec

Each domain has a markdown file in `domains/`. It contains:
- Purpose (what the domain does)
- Key Files (source file paths)
- Core Types (Go type definitions)
- Flow (ASCII diagrams of happy paths)
- Invariants (what ALWAYS holds true)
- Extension Points (how to extend without breaking)

### Step 3: Contracts

When a task crosses package boundaries, read the relevant contract in `contracts/`. Contracts document initialization order, data flow, and breaking change checklists.

---

## 3. Document Formats

The system uses 5 strictly defined formats. Every new document MUST follow the corresponding template from `META.md`.

1. **Domain** — `domains/*.md` (9 required sections)
2. **Domain Detail** — `domains/*/<component>.md` (7 required sections — for multi-component domains)
3. **Contract** — `contracts/*.md` (7 required sections)
4. **Architecture** — `architecture/*.md` (4+ required sections)
5. **ADR** — `decisions/NNN-slug.md` (5 required sections)

---

## 4. Cross-References

Rules for linking between specs:

```markdown
<!-- To another spec (relative path from specs/) -->
[Configuration](domains/configuration.md)

<!-- To a section within another spec -->
[Contract: Config → Logging](contracts/config-logging.md#data-flow-across-boundary)

<!-- To source code (backticks, path from repo root) -->
`internal/config/config.go`
```

Rule: all links are **relative from `specs/`**. Section anchors — lowercase, hyphen-separated.

---

## 5. Update Protocol

### When to Update

- After any change that alters documented behavior
- After adding/removing/renaming interfaces from contracts
- After changing architectural boundaries or invariants
- After a new architectural decision → create an ADR
- After implementing a new Phase that adds packages or domains

### How to Update

1. **Read** the current spec fully before modifying
2. **Preserve the format** — sections and their order are defined in META.md
3. **Update cross-references** if file paths changed
4. **Update INDEX.md** after adding or removing a spec file
5. **ADRs are immutable** — if `Status: Accepted`, create a new ADR with a `Superseded by` link

### Validation Checklist

After updating, verify:

- [ ] All sections from the template are present
- [ ] Cross-references point to existing files
- [ ] Paths in Key Files are accurate
- [ ] Invariants are stated affirmatively
- [ ] INDEX.md reflects the current file set

---

## 6. Workflow for Typical Tasks

### "Implement a new Phase (adds new internal packages)"

1. Read [Architecture: Layers](architecture/layers.md) — understand import rules
2. Read [Contract: Main ↔ Internal](contracts/main-internal.md) — understand startup wiring
3. **After implementation**: create domain spec(s) for new package(s), update contracts, update `INDEX.md`

### "Add a new config field"

1. Read [Configuration](domains/configuration.md) — understand Config struct, defaults, validation flow
2. Add field to the appropriate `*Config` struct in `internal/config/config.go`
3. Add default in `internal/config/defaults.go` (`applyDefaults()`)
4. Add validation in `internal/config/validation.go` (`validate()`)
5. Add test case in `internal/config/config_test.go`
6. Update [Configuration spec](domains/configuration.md) and `configs/tobimaru.yaml`

### "Add cleanup logic for a new component"

1. Read [Lifecycle](domains/lifecycle.md) — understand `shutdown.Manager` API
2. In `cmd/tobimaru/main.go`, add `sm.Register("component_name", cleanupFn)` after component initialization
3. Ensure cleanup runs in correct LIFO order relative to other hooks

### "Modify the build system"

1. Read [Build & Versioning](domains/build-and-versioning.md) — understand Makefile targets, ldflags, CI
2. Read [ADR-002](decisions/002-ldflags-version.md) — understand why ldflags was chosen
3. Make changes to `Makefile` and/or `.github/workflows/ci.yml`
4. Update [Build & Versioning spec](domains/build-and-versioning.md)

### "Understand why X was designed a certain way"

1. Search in `decisions/` — there may already be an ADR
2. If not — look at the `## Invariants` section of the corresponding domain spec

---

## 7. Working with ADRs

### Creating a New ADR

1. Determine the next sequential number (check existing ones in `decisions/`)
2. Copy the template from `decisions/_template.md`
3. Fill in all sections
4. Add an entry to `INDEX.md`

### Superseding a Decision

1. Create a new ADR with the updated decision
2. In the old ADR, change `## Status` to `Superseded by [NNN](./NNN-slug.md)`
3. This is the only permissible edit to an accepted ADR

---

## 8. Content Formatting Principles

### Invariants — Affirmative Only

```markdown
<!-- Correct -->
- The logger always writes to os.Stdout.
- Hooks execute in reverse registration order (LIFO).

<!-- Incorrect -->
- The logger should not write to stderr.
- Don't execute hooks in registration order.
```

### Key Files — From Repository Root

```markdown
## Key Files

- `internal/config/config.go` — Config structs and Load/LoadReader functions
- `internal/shutdown/shutdown.go` — Manager struct and shutdown orchestration
```

### Tables for Reference Information

Tables are the preferred format for: interface catalogs, config field mappings, Makefile targets, CI job summaries, decision tables.

### ASCII Diagrams

For flows and architecture — ASCII art (not Mermaid), to work without a renderer.

---

## 9. Anti-Patterns

| Anti-pattern | Why it's bad | What to do instead |
| --- | --- | --- |
| Mirror file structure in specs | One file may participate in multiple domains | Organize by conceptual domains |
| Generate specs from code | Loses the ability to detect discrepancies | Write manually, compare with code |
| Skip updating INDEX.md | Agent won't find the new spec | Always update when adding/removing |
| Edit an accepted ADR | Loses decision history | Create a new ADR with `Superseded by` |
| State invariants negatively | Harder to verify compliance | Use affirmative phrasing |
| Add filler prose | Wastes the agent's context window | Only necessary and sufficient information |

---

## 10. Quick Start (TL;DR)

1. **Need to learn something** → `specs/INDEX.md` → find task → go to spec
2. **Need to change code** → read domain spec + contract → implement → update spec
3. **Need a new decision** → create ADR from template → update INDEX.md
4. **Need to add a new Phase** → read layers.md + main-internal.md → implement → create domain specs
5. **Formats, rules, templates** → `specs/META.md`
