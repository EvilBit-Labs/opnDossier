---
title: CLI flag --include-tunables ignored in convert and display commands
category: logic-errors
date: 2026-03-18
tags: [cli-flags, converter, display, tunables, cobra, options-struct, silent-failure]
component: cmd (convert, display), converter, builder
symptoms:
  - Flag accepted but had no effect on output
  - convert command stored flag in untyped CustomFields map that was never read
  - display command never passed flag to converter at all
severity: high
issue: 412
pr: 413
---

# CLI Flag `--include-tunables` Silently Ignored

## Problem

The `--include-tunables` CLI flag was accepted by both `convert` and `display` commands but had zero effect on output. No error, no warning -- the flag simply did nothing. Users expecting filtered tunables got all tunables (or none), with no indication the flag was broken.

**Symptoms:**

- `opndossier convert config.xml --include-tunables` produced identical output to `opndossier convert config.xml`
- `opndossier display config.xml --include-tunables` had no effect
- No error messages or warnings

## Root Cause

Two independent failures in the flag-to-builder data flow:

### 1. Display command: flag never wired

`cmd/display.go`'s `buildDisplayOptions()` simply never included a line to transfer `sharedIncludeTunables` into `opt.IncludeTunables`. The flag was parsed by Cobra, stored in the package-level variable, and then ignored.

### 2. Convert command: untyped map, unread consumer

`cmd/convert.go` stored the flag in `opt.CustomFields["IncludeTunables"]` -- an untyped `map[string]any`. The `MarkdownBuilder` had no code to read from this map. The flag value was dutifully stored and never consumed.

**Why this was hard to catch:** No compile-time error. The `CustomFields` map accepted any key silently. The builder compiled and ran without error -- it just never checked the map. Unit tests verified the flag was stored in `CustomFields` but never verified it affected output.

## Solution

### Core fix: typed field + direct wiring

```go
// Before (convert.go) -- untyped, never read
opt.CustomFields["IncludeTunables"] = sharedIncludeTunables

// After (convert.go AND display.go) -- typed, compile-checked
opt.IncludeTunables = sharedIncludeTunables
```

### Options struct

Added `IncludeTunables bool` as a first-class field on `converter.Options`, replacing the `CustomFields` map entry. Added `WithIncludeTunables()` builder method for functional-style construction.

### ReportBuilder interface

Added `SetIncludeTunables(bool)` directly to the `ReportBuilder` interface. The builder reads the flag and passes sysctl data through `formatters.FilterSystemTunables()` before rendering. The ToC "System Tunables" link is conditional on filtered results being non-empty.

### Filtering architecture

Filtering happens at the builder layer (not `prepareForExport()`). This is deliberate: JSON/YAML exports should always include all tunables (structured data should be complete); filtering is a presentation concern for markdown/text/HTML.

### Additional improvements during review

- Expanded `securitySysctlPrefixes` with 11 new FreeBSD sysctl prefixes
- Converted prefix list from mutable `var` to function (immutability)
- Extracted shared ToC helpers (eliminated 3-way duplication)
- Added regression tests for both `convert` and `display` flag wiring

## Key Files Changed

| File                                            | Change                                              |
| ----------------------------------------------- | --------------------------------------------------- |
| `cmd/display.go`                                | Added `opt.IncludeTunables = sharedIncludeTunables` |
| `cmd/convert.go`                                | Changed from `CustomFields` to direct field         |
| `internal/converter/options.go`                 | Added typed `IncludeTunables` field                 |
| `internal/converter/builder/builder.go`         | `SetIncludeTunables` on interface + ToC helpers     |
| `internal/converter/builder/writer.go`          | Streaming path tunables filtering                   |
| `internal/converter/hybrid_generator.go`        | Calls `SetIncludeTunables` before generation        |
| `internal/converter/formatters/transformers.go` | Expanded prefix list, immutable function            |

## Prevention Strategies

### 1. Use typed fields, not untyped maps

The `CustomFields map[string]any` pattern hides bugs. A missing or misspelled key returns `nil` at runtime with no error. Typed struct fields produce compile-time errors when accessed incorrectly.

**Rule:** Never use `CustomFields` for flags that affect rendering behavior. Add a typed field to `Options`.

### 2. Regression test for every flag path

When adding a shared flag, add a test for EACH command that uses it:

```go
func TestBuildConversionOptionsIncludeTunables(t *testing.T) {
    sharedIncludeTunables = true
    result := buildConversionOptions("json", nil)
    assert.Equal(t, true, result.IncludeTunables)
}

func TestBuildDisplayOptionsIncludeTunables(t *testing.T) {
    sharedIncludeTunables = true
    result := buildDisplayOptions(nil)
    assert.Equal(t, true, result.IncludeTunables)
}
```

### 3. Update `sharedFlagSnapshot` for new flags

AGENTS.md section 7.7 documents this: when adding new shared flags, update `sharedFlagSnapshot` in `cmd/display_test.go` -- add the field to the struct, `captureSharedFlags()`, and `restore()`. Missing fields leak state between tests.

### 4. Diff output with flag on vs. off

If a flag is supposed to change output, verify it actually does. A flag that produces identical output with and without is broken.

## Warning Signs

- A new CLI flag that doesn't break any existing golden files or tests
- `CustomFields` map access without checking if the key exists
- Flag added to one command but not another that shares the same flags
- Test verifies flag storage but not output effect
- Output identical with and without the flag

## Related Documentation

- [AGENTS.md section 5.7](../../AGENTS.md) -- CommandContext Pattern
- [AGENTS.md section 7.7](../../AGENTS.md) -- Testing Global Flag Variables
- [GOTCHAS.md section 1.1](../../GOTCHAS.md) -- t.Parallel() and Global State
- [GitHub Issue #412](https://github.com/EvilBit-Labs/opnDossier/issues/412) -- Original bug report
- [PR #413](https://github.com/EvilBit-Labs/opnDossier/pull/413) -- Fix implementation
