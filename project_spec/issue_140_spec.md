# Technical Specification: Issue #140

## Architecture: Reduce Global State in cmd Package with CommandContext Pattern

**Issue URL:** https://github.com/EvilBit-Labs/opnDossier/issues/140 **Milestone:** v1.2 (Performance & Enterprise Features) **Labels:** enhancement, architecture, refactoring

---

## Issue Summary

The `cmd` package uses package-level global variables with `//nolint:gochecknoglobals` directives. While this is acceptable for Cobra patterns, it creates hidden dependencies and makes testing harder.

---

## Problem Statement

### Current State

The `cmd` package declares 24 package-level variables across three files:

**`cmd/root.go` (lines 17-36):**

```go
var (
    cfgFile string                // CLI config file path
    Cfg    *config.Config         // Application configuration
    logger *log.Logger            // Application logger
    buildDate = "unknown"         // Build information
    gitCommit = "unknown"         // Build information
)
var defaultLoggerConfig = log.Config{...}  // Logger config
var rootCmd = &cobra.Command{...}          // Root command
```

**`cmd/convert.go` (lines 27-40):**

```go
var (
    outputFile string  // Output file path
    format     string  // Output format
    force      bool    // Force overwrite
)
var ErrOperationCancelled = errors.New(...)
var ErrFailedToEnrichConfig = errors.New(...)
var ErrUnsupportedOutputFormat = errors.New(...)
var convertCmd = &cobra.Command{...}
```

**`cmd/shared_flags.go` (lines 9-17):**

```go
var (
    sharedSections        []string  // Sections to include
    sharedTheme           string    // Theme for rendering
    sharedWrapWidth       = -1      // Text wrap width
    sharedNoWrap          bool      // Disable text wrapping
    sharedIncludeTunables bool      // Include system tunables
    sharedComprehensive   bool      // Comprehensive report
)
```

**`cmd/display.go` (line 34):**

```go
var displayCmd = &cobra.Command{...}
```

**`cmd/validate.go` (line 20):**

```go
var validateCmd = &cobra.Command{...}
```

### Problems

1. **Hidden Dependencies:** Commands implicitly depend on global state that can be modified from anywhere
2. **Testing Challenges:** Tests require careful setup/teardown of global variables (seen in test files with `t.Cleanup` patterns)
3. **Data Flow Opacity:** Harder to trace how configuration flows through the application
4. **Concurrency Risks:** While current tests handle this, global state in concurrent tests needs careful coordination
5. **Mock Injection Difficulty:** Requires modifying globals rather than passing test doubles

---

## Technical Approach

### Design: CommandContext Pattern

Introduce a `CommandContext` struct that encapsulates shared state:

```go
// CommandContext encapsulates shared state for all CLI commands.
// It is set on the cobra.Command context during PersistentPreRunE.
type CommandContext struct {
    Config *config.Config
    Logger *log.Logger
}

// contextKey is the type for context keys to avoid collisions.
type contextKey string

// cmdContextKey is the key used to store CommandContext in context.Context.
const cmdContextKey contextKey = "opnDossierCmdContext"

// GetCommandContext retrieves the CommandContext from a cobra.Command.
// Returns nil if not found.
func GetCommandContext(cmd *cobra.Command) *CommandContext {
    if ctx := cmd.Context(); ctx != nil {
        if cmdCtx, ok := ctx.Value(cmdContextKey).(*CommandContext); ok {
            return cmdCtx
        }
    }
    return nil
}

// SetCommandContext stores the CommandContext in the command's context.
func SetCommandContext(cmd *cobra.Command, cmdCtx *CommandContext) {
    ctx := context.WithValue(cmd.Context(), cmdContextKey, cmdCtx)
    cmd.SetContext(ctx)
}
```

### Migration Strategy

**Phase 1:** Introduce `CommandContext` alongside existing globals (backward compatible) **Phase 2:** Migrate commands to use context pattern **Phase 3:** Remove deprecated globals (keep only essential Cobra patterns)

### What Stays Global (Acceptable Cobra Patterns)

- `rootCmd`, `convertCmd`, `displayCmd`, `validateCmd` - Cobra command definitions
- `buildDate`, `gitCommit` - Build-time ldflags injection
- `defaultLoggerConfig` - Test override hook
- Sentinel errors (`ErrOperationCancelled`, etc.)

### What Moves to CommandContext

- `Cfg` (configuration)
- `logger` (application logger)
- Flag variables (`outputFile`, `format`, `force`, `sharedSections`, etc.)

---

## Implementation Plan

### Task 1: Create CommandContext Infrastructure

**File:** `cmd/context.go` (new file)

1. Define `CommandContext` struct
2. Define `contextKey` type and constant
3. Implement `GetCommandContext()` function
4. Implement `SetCommandContext()` function
5. Add tests in `cmd/context_test.go`

**Acceptance Criteria:**

- New file created with proper package declaration
- All functions documented with Go doc comments
- Tests cover normal and edge cases
- `just lint` passes
- `just test` passes

### Task 2: Migrate Root Command Setup

**File:** `cmd/root.go`

1. Modify `PersistentPreRunE` to create and set `CommandContext`
2. Keep `GetLogger()` and `GetConfig()` for backward compatibility (deprecated)
3. Add deprecation comments directing to context pattern
4. Update tests in `cmd/root_test.go`

**Acceptance Criteria:**

- CommandContext is set during PersistentPreRunE
- Existing tests continue to pass
- GetLogger/GetConfig work but are marked deprecated
- `just ci-check` passes

### Task 3: Migrate Convert Command

**File:** `cmd/convert.go`

1. Add `ConvertFlags` struct to hold convert-specific flags
2. Modify `RunE` to get logger/config from CommandContext
3. Remove direct access to global `logger` and `Cfg`
4. Update `buildConversionOptions` to accept CommandContext
5. Update tests in `cmd/convert_test.go`

**Acceptance Criteria:**

- Convert command uses CommandContext for config/logger
- No direct access to global Cfg/logger in RunE
- All existing tests pass
- `just ci-check` passes

### Task 4: Migrate Display Command

**File:** `cmd/display.go`

1. Modify `RunE` to get logger/config from CommandContext
2. Update `buildDisplayOptions` to accept CommandContext
3. Remove direct access to globals
4. Update tests in `cmd/display_test.go`

**Acceptance Criteria:**

- Display command uses CommandContext
- All existing tests pass
- `just ci-check` passes

### Task 5: Migrate Validate Command

**File:** `cmd/validate.go`

1. Modify `RunE` to get logger/config from CommandContext
2. Remove direct access to global `logger`
3. Update tests

**Acceptance Criteria:**

- Validate command uses CommandContext
- All existing tests pass
- `just ci-check` passes

### Task 6: Consolidate Shared Flags

**File:** `cmd/shared_flags.go`

1. Create `SharedFlags` struct to hold shared flag values
2. Add method to extract SharedFlags from CommandContext
3. Update `addSharedTemplateFlags` to bind to context
4. Update all consumers

**Acceptance Criteria:**

- SharedFlags struct exists with all shared flag values
- Commands extract flags from context, not globals
- `just ci-check` passes

### Task 7: Final Cleanup and Documentation

**Files:** All cmd/\*.go files, AGENTS.md

1. Remove deprecated globals (Cfg, logger exports)
2. Remove `//nolint:gochecknoglobals` where no longer needed
3. Update AGENTS.md with CommandContext pattern documentation
4. Ensure all tests pass
5. Run full CI check

**Acceptance Criteria:**

- No unnecessary global variables remain
- Documentation updated
- `just ci-check` passes
- All tests pass including race detection

---

## Test Plan

### Unit Tests

1. **Context Tests (`cmd/context_test.go`):**

   - Test `GetCommandContext` with valid context
   - Test `GetCommandContext` with nil context
   - Test `GetCommandContext` with missing key
   - Test `SetCommandContext` properly stores context

2. **Command Integration Tests:**

   - Verify CommandContext is available in PreRunE
   - Verify CommandContext is available in RunE
   - Test context propagation to subcommands

3. **Backward Compatibility Tests:**

   - Ensure GetLogger() still works (deprecated)
   - Ensure GetConfig() still works (deprecated)

### Race Detection

```bash
go test -race ./cmd/...
```

### Coverage Target

Maintain >80% coverage on cmd package.

---

## Files to Modify/Create

### New Files

| File                  | Purpose                                    |
| --------------------- | ------------------------------------------ |
| `cmd/context.go`      | CommandContext struct and helper functions |
| `cmd/context_test.go` | Tests for context functionality            |

### Modified Files

| File                       | Changes                                                                       |
| -------------------------- | ----------------------------------------------------------------------------- |
| `cmd/root.go`              | Create/set CommandContext in PersistentPreRunE, deprecate GetLogger/GetConfig |
| `cmd/root_test.go`         | Add context-aware tests                                                       |
| `cmd/convert.go`           | Use CommandContext instead of globals                                         |
| `cmd/convert_test.go`      | Update tests to use context pattern                                           |
| `cmd/display.go`           | Use CommandContext instead of globals                                         |
| `cmd/display_test.go`      | Update tests if needed                                                        |
| `cmd/validate.go`          | Use CommandContext instead of globals                                         |
| `cmd/shared_flags.go`      | Create SharedFlags struct                                                     |
| `cmd/shared_flags_test.go` | Update tests for SharedFlags                                                  |
| `AGENTS.md`                | Document CommandContext pattern                                               |

---

## Success Criteria

1. **Reduced Global State:** Only acceptable Cobra patterns remain as globals
2. **Explicit Dependencies:** Commands receive context explicitly via CommandContext
3. **Easier Testing:** Tests can inject mock contexts without global state manipulation
4. **Clear Data Flow:** Configuration and logger flow is traceable through context
5. **All Tests Pass:** Including race detection
6. **CI Green:** `just ci-check` passes
7. **Documentation Updated:** AGENTS.md includes CommandContext guidance

---

## Out of Scope

1. **Restructuring cmd package into multiple packages** - Keep single package
2. **Changing Cobra command registration pattern** - Commands stay as package-level vars
3. **Modifying how ldflags injection works** - buildDate/gitCommit stay global
4. **Changing sentinel error definitions** - Errors stay as package-level vars
5. **Performance optimization** - This is a refactoring task
6. **Adding new CLI commands or flags** - Scope limited to existing functionality

---

## Risk Assessment

| Risk                                      | Mitigation                                                         |
| ----------------------------------------- | ------------------------------------------------------------------ |
| Breaking existing tests                   | Phase migration, maintain backward compatibility during transition |
| Introducing bugs in command execution     | Comprehensive test coverage, race detection                        |
| Merge conflicts with parallel development | Keep changes atomic, avoid large PRs                               |
| CI failures                               | Run `just ci-check` at each phase                                  |

---

## References

- [Cobra Context Documentation](https://pkg.go.dev/github.com/spf13/cobra#Command.Context)
- [Go Context Best Practices](https://go.dev/blog/context)
- [Effective Go - Package-level Variables](https://go.dev/doc/effective_go#package-names)
