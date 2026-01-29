# CLI Interface Enhancement Implementation Plan

**Issue:** #9 - Epic: CLI Interface Enhancement **Branch:** 140-architecture-reduce-global-state-in-cmd-package-with-commandcontext-pattern **Tasks:** TASK-021 through TASK-025

## Execution Order Rationale

The phases are ordered to build on each other:

1. **Phase 1 (Foundation)** must come first - establishes the command structure that other phases depend on
2. **Phase 2 (Help System)** builds on the organized command structure
3. **Phase 3 (Output Modes)** enhances existing verbose/quiet infrastructure
4. **Phase 4 (Progress)** uses output mode infrastructure for respecting flags
5. **Phase 5 (Tab Completion)** adds completion functions to the finalized command structure

---

## Phase 1: Command Structure Foundation (TASK-021)

### Objective

Refactor CLI command structure with improved flag organization and validation.

### Files to Modify

- `cmd/root.go` - Enhanced flag annotations, command groups
- `cmd/convert.go` - ValidArgsFunction, improved PreRunE
- `cmd/display.go` - ValidArgsFunction, improved PreRunE
- `cmd/validate.go` - ValidArgsFunction, improved PreRunE
- `cmd/shared_flags.go` - Additional flag categories

### Implementation Steps

#### Step 1.1: Enhance Flag Annotations

- Add comprehensive category annotations to all flags
- Categories: configuration, output, logging, progress, display, content, formatting, audit

#### Step 1.2: Add ValidArgsFunction to Commands

- `convert`: Complete XML files, formats
- `display`: Complete XML files, themes
- `validate`: Complete XML files

#### Step 1.3: Refine Command Groups

- Add descriptions to command groups
- Ensure all commands are in appropriate groups
- Move completion and man to utility group

### Verification

```bash
just ci-check
go test ./cmd/... -v
```

---

## Phase 2: Comprehensive Help System (TASK-022)

### Objective

Implement styled help with examples and suggestions.

### Files to Create

- `cmd/help.go` - Custom help templates and suggestion logic

### Files to Modify

- `cmd/root.go` - Register custom help template

### Implementation Steps

#### Step 2.1: Create Custom Help Template

- Use Cobra's SetHelpTemplate with markdown-style formatting
- Group flags by category in help output
- Add examples section to help template

#### Step 2.2: Implement Typo Suggestions

- Set SuggestionsMinimumDistance on root command
- Create custom suggestion function for context-aware hints

#### Step 2.3: Add Help Flags

- `--help-examples`: Show only examples
- Integrate with existing help system

### Verification

```bash
just ci-check
./opnDossier --help
./opnDossier convert --help
./opnDossier invlid  # Test typo suggestions
```

---

## Phase 3: Enhanced Output Modes (TASK-023)

### Objective

Enhance verbose/quiet modes with granular control.

### Files to Modify

- `cmd/root.go` - Exit code documentation, JSON error output
- `cmd/convert.go` - Structured error handling
- `cmd/validate.go` - Structured error handling, exit codes

### Implementation Steps

#### Step 3.1: Implement Structured Exit Codes

- Exit 0: Success
- Exit 1: General error
- Exit 2: Parse error
- Exit 3: Validation error

#### Step 3.2: Enhance JSON Output Mode

- Implement `--json-output` for machine-readable errors
- Structure: `{"error": "message", "code": N, "details": {}}`

#### Step 3.3: Verify Minimal Mode

- Ensure `--minimal` flag works correctly
- Between quiet and normal output levels

### Verification

```bash
just ci-check
./opnDossier --json-output validate nonexistent.xml 2>&1
./opnDossier --quiet convert testdata/config.xml
```

---

## Phase 4: Progress Indicators (TASK-024)

### Objective

Implement progress feedback for long-running operations.

### Files to Create

- `internal/progress/progress.go` - Progress interface
- `internal/progress/spinner.go` - Spinner implementation
- `internal/progress/bar.go` - Bar implementation (refactor from display)
- `internal/progress/noop.go` - NoOp for quiet mode

### Files to Modify

- `cmd/convert.go` - Integrate progress for multi-file processing
- `internal/display/display.go` - Use new progress interface

### Implementation Steps

#### Step 4.1: Create Progress Interface

```go
type Progress interface {
    Start(message string)
    Update(percent float64, message string)
    Complete(message string)
    Fail(err error)
}
```

#### Step 4.2: Implement Progress Types

- `SpinnerProgress` - For indeterminate operations
- `BarProgress` - For determinate operations (refactor existing)
- `NoOpProgress` - For quiet/non-TTY

#### Step 4.3: Integrate in Convert Command

- Show progress during multi-file processing
- Respect `--no-progress` and `--quiet` flags

### Verification

```bash
just ci-check
./opnDossier convert testdata/*.xml --format json
./opnDossier --no-progress convert testdata/config.xml
```

---

## Phase 5: Tab Completion (TASK-025)

### Objective

Add comprehensive tab completion support.

### Files to Modify

- `cmd/completion.go` - Enhanced completion with descriptions
- `cmd/convert.go` - Flag completion functions
- `cmd/display.go` - Flag completion functions
- `cmd/validate.go` - Flag completion functions

### Implementation Steps

#### Step 5.1: Add File Completion

- Filter to `*.xml` files for config arguments
- Add directory completion support

#### Step 5.2: Add Flag Value Completion

- `--format`: markdown, json, yaml
- `--theme`: light, dark, auto, none
- `--section`: system, network, firewall, services, security
- `--color`: auto, always, never

#### Step 5.3: Enhance Completion Command

- Add descriptions to completions
- Improve shell-specific documentation

### Verification

```bash
just ci-check
./opnDossier completion bash > /tmp/completion.bash
source /tmp/completion.bash
# Test: opnDossier convert <TAB>
```

---

## Commit Strategy

After each phase passes `just ci-check`:

```bash
git add -A
git commit -m "feat(cli): <phase description>

Implements TASK-02X from issue #9.

- <bullet point changes>

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

## Success Criteria

- [ ] All phases implemented
- [ ] `just ci-check` passes after each phase
- [ ] No breaking changes to existing CLI
- [ ] Test coverage maintained >80%
