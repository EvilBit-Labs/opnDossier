---
title: 'File-Split Refactoring: Pre-commit Hooks and Test Breakage'
category: architecture-issues
date: 2026-03-18
tags: [refactoring, file-split, pre-commit, testing, validator]
related_issues: ['#319', '#415']
components: [internal/validator, internal/processor]
---

# File-Split Refactoring: Pre-commit Hooks and Test Breakage

## Problem

When splitting `internal/validator/opnsense.go` (1,061 lines) into domain-specific files, two non-obvious issues occurred:

1. **Pre-commit hooks silently rearranged helpers.** After creating the new files and trimming the orchestrator, the pre-commit formatter moved domain-specific helpers back into `opnsense.go`, creating a different layout than intended.
2. **Changing an unexported function signature broke tests.** Optimizing `validateInterface` to accept a pre-computed `map[string]struct{}` instead of `*schema.Interfaces` broke two test call sites that called the unexported function directly.

## Root Cause

1. **Hook rearrangement:** `gofumpt` and linters run via `pre-commit` can reformat and reorder code. When helpers are moved to new files but the orchestrator file is also modified, the formatter may consolidate related declarations back into the larger file based on its own heuristics.

2. **Test coupling:** Go test files in the same package can call unexported functions directly. When a file split changes a function's parameter type (even for a pure optimization like pre-computing a map), every test call site must be updated.

## Solution

### For pre-commit hook interference

After writing new files and trimming the orchestrator, always re-read the files to verify the hook didn't rearrange them:

```bash
# After the split, verify contents match intent
wc -l internal/validator/*.go  # Check line counts
go build ./internal/validator/  # Verify no duplicates
```

### For test breakage on signature changes

Before changing any unexported function signature, grep for all call sites:

```bash
# Find all callers of the function across test files
grep -rn 'validateInterface(' internal/validator/*_test.go
```

Then update each call site. In this case, wrapping the argument:

```go
// Before (old signature: accepts *schema.Interfaces)
errors := validateInterface(&tt.iface, "test", interfaces)

// After (new signature: accepts map[string]struct{})
errors := validateInterface(&tt.iface, "test", collectInterfaceNames(interfaces))
```

### For pre-existing issues found during split

CodeRabbit review caught 4 pre-existing issues in the moved code. Per project policy ("Zero tolerance for tech debt"), all were fixed in the same PR:

- `isValidIP` called `net.ParseIP` twice -- cached the result
- GID/UID error messages said "positive integer" but allowed 0 -- fixed to "non-negative integer"
- `validateDhcpd` docstring didn't start with function name -- fixed per Go conventions
- `collectInterfaceNames` called per-interface in O(N^2) loop -- pre-computed once

## Prevention

1. **Always re-verify file contents after pre-commit hooks run** during file-split refactors
2. **Grep `*_test.go` for call sites** before changing any unexported function signature
3. **Run `just ci-check`** after every file-split refactor -- it catches duplicate declarations, test failures, and lint issues in one pass
4. **Treat code review findings on moved code as in-scope** -- the "zero tech debt" policy means pre-existing issues in touched code get fixed now, not later
