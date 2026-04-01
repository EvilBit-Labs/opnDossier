---
title: Centralize format dispatch via FormatRegistry to eliminate scattered switch statements
category: architecture-issues
date: '2026-03-20'
tags:
  - refactoring
  - registry-pattern
  - format-handling
  - centralization
  - silent-failures
  - atomic-mutation
  - thread-safety
component: internal/converter/registry.go
severity: high
symptoms:
  - Adding a new output format required updates in 8+ locations
  - Format aliases worked in some code paths but not others
  - Silent .md fallback masked file extension lookup failures
  - StripMarkdownFormatting silently returned raw markdown on goldmark error
  - Canonical() returned unknown formats without indicating failure
  - Register() left registry in partial state on alias validation panic
  - Shared HybridGenerator across parallel test subtests caused data races
related_issues:
  - '#325'
  - '#434'
related_docs:
  - docs/solutions/architecture-issues/file-split-refactor-gotchas.md
  - docs/solutions/logic-errors/documentation-code-drift-interface-refactoring.md
  - docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md
---

# Centralize Format Dispatch via FormatRegistry

## Problem

Format dispatch logic for output formats (markdown, json, yaml, text, html) was scattered across 8+ locations:

- `cmd/convert.go` -- format constants, alias constants, file extension switch, normalizeFormat switch, generateOutputByFormat switch, validateConvertFlags list
- `internal/converter/hybrid_generator.go` -- Generate and GenerateToWriter switch statements
- `internal/converter/options.go` -- Format.Validate switch
- `internal/config/validation.go` -- ValidFormats list
- `cmd/shared_flags.go` -- shell completion list
- `internal/processor/processor.go` -- Transform switch (no alias resolution)

Adding a new format required coordinating updates across all locations. Missing one caused silent inconsistencies -- a format valid in one location might be rejected or produce wrong output elsewhere.

## Root Cause

No single source of truth for format metadata. Each consumer maintained its own copy of format names, aliases, extensions, and validation logic. The scattered duplication was a classic maintenance hazard that accumulated over time as new formats (text, html) were added.

## Investigation Steps

1. Mapped all locations that referenced format names by grepping for switch statements, constant definitions, and format validation
2. Identified 8+ distinct locations requiring synchronized updates
3. Designed a FormatRegistry pattern following the `database/sql` driver registration idiom
4. Implemented registry with FormatHandler interface, then systematically replaced each scattered location
5. During code review (5 parallel review agents), discovered 7 additional issues in the implementation
6. Fixed all issues through a triage-and-resolve workflow with parallel fix agents

## Solution

### FormatRegistry as Single Source of Truth

Introduced `internal/converter/registry.go` with:

- **FormatHandler interface** -- `FileExtension()`, `Aliases()`, `Generate()`, `GenerateToWriter()` per format
- **FormatRegistry struct** -- thread-safe registry with `Register`, `Get`, `Canonical`, `ValidFormats`, `ValidFormatsWithAliases`, `Extensions`
- **DefaultRegistry singleton** -- 5 built-in handlers registered at package init
- **Handler dispatch** -- replaces switch statements in HybridGenerator

Adding a new format now requires only registering a FormatHandler in `newDefaultRegistry()`.

### Additional Issues Found and Fixed During Review

| Issue                                                   | Root Cause                                               | Fix                                  |
| ------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------ |
| Silent `.md` fallback in file extension                 | Defensive default masked registry bugs                   | Replace with error propagation       |
| `StripMarkdownFormatting` returns raw markdown on error | `string` return type hides failures                      | Changed to `(string, error)`         |
| `Canonical()` passthrough for unknowns                  | `string` return hides unresolved formats                 | Changed to `(string, bool)`          |
| `Register()` partial mutation on panic                  | Handler inserted before alias validation                 | Validate-before-mutate pattern       |
| Empty format name accepted                              | No input validation                                      | Panic on empty/whitespace            |
| Inconsistent TrimSpace normalization                    | Register trimmed but Get/Canonical did not               | Added TrimSpace to all entry points  |
| Shared HybridGenerator in parallel tests                | MarkdownBuilder not thread-safe                          | Per-subtest generator creation       |
| Handler parameter inconsistency                         | JSON/YAML extracted opts.Redact, others passed full opts | All methods accept Options uniformly |
| `handlerForFormat` redundant Canonical+Get              | Get already resolves aliases                             | Call Get directly                    |

## Prevention Strategies

### Centralize Dispatch Logic

When multiple code locations need to dispatch by type/format/mode, introduce a registry immediately. Do not scatter switch statements. The registry pattern from `database/sql` is well-proven in Go.

### Return Errors, Not Silent Fallbacks

Functions accepting user-controlled input must return `(T, error)` or `(T, bool)`. Never silently return a default on failure. Silent fallbacks mask bugs and make debugging harder.

### Validate Before Mutating

Registry `Register()` methods must validate all conditions (duplicates, alias conflicts, nil handlers, empty names) before any map mutations. Build the list of changes, validate all of them, then commit atomically.

### Keep Input Normalization Consistent

If `Register()` normalizes input (TrimSpace, ToLower), every lookup method (`Get`, `Canonical`) must apply the same normalization. Inconsistency causes lookup failures for inputs with whitespace.

### Per-Instance State in Parallel Tests

When a struct has mutable state (like MarkdownBuilder), create a fresh instance per parallel subtest. Never share mutable state across goroutines.

## Verification Checklist

- [ ] `grep -rn "switch.*format" --include='*.go' .` returns only registry/handler code
- [ ] `grep -rn "const.*Format" --include='*.go' .` returns only `internal/converter/` constants
- [ ] Shell completions derive from `DefaultRegistry.ValidFormats()`
- [ ] `Format.Validate()` delegates to registry
- [ ] `config.ValidFormats` derives from registry with `slices.Clone()`
- [ ] `processor.Transform()` resolves aliases via `Canonical()`
- [ ] `go test -race ./internal/converter/...` passes
- [ ] `just ci-check` passes

## Related Documentation

- [AGENTS.md section 5.9b](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md) -- FormatRegistry Pattern documentation
- [architecture.md](../../development/architecture.md) -- FormatRegistry Integration section
- [documentation-code-drift-interface-refactoring.md](../logic-errors/documentation-code-drift-interface-refactoring.md) -- documentation accuracy guidelines
