# opnDossier Architecture Review

**Generated:** 2026-01-14 **Reviewer:** Architecture Analysis **Codebase Size:** ~40,000 lines of Go code **Test Files:** 61 test files

---

## Executive Summary

opnDossier demonstrates **strong architectural foundations** with excellent separation of concerns, comprehensive error handling, and modern Go idioms. The codebase is well-structured for maintainability and follows industry best practices. Key strengths include a clean plugin architecture, streaming XML processing, and comprehensive testing. Areas for improvement include reducing global state and consolidating redundant converter patterns.

**Overall Grade: A-** (Strong architecture with minor improvement opportunities)

---

## 1. Overall Structure and Patterns

### 1.1 Package Organization

**STRENGTHS:**

```
internal/
├── audit/           # Audit engine and plugin lifecycle
├── cfgparser/       # XML parsing with security (streaming, XXE prevention)
├── compliance/      # Plugin interfaces (Plugin, Finding, Control)
├── config/          # Configuration management (Viper)
├── constants/       # Shared constants (validation whitelists)
├── converter/       # Format converters (JSON/YAML/Markdown/Text/HTML)
│   └── builder/     # Markdown builder and writer
├── diff/            # Configuration diff engine
├── display/         # Terminal display logic (Lipgloss/Glamour)
├── docgen/          # Model documentation generation
├── export/          # File export functionality
├── logging/         # Structured logging (wraps charmbracelet/log)
├── markdown/        # Markdown generation (hybrid approach)
├── model/           # Data models and re-export seam
│   ├── common/      # Platform-agnostic CommonDevice domain model
│   └── opnsense/    # Schema → CommonDevice converter
├── plugins/         # Compliance plugins (firewall/SANS/STIG)
├── pool/            # Worker pool for concurrent processing
├── processor/       # Core processing and analysis
├── progress/        # CLI progress indicators (spinner, bar)
├── sanitizer/       # Data sanitization (redaction rules engine)
├── schema/          # Canonical OPNsense data model (XML structs)
├── testing/         # Shared test helpers
└── validator/       # Configuration validation
```

**Evaluation:**

- Clean separation by responsibility
- No circular dependencies observed
- Clear boundaries between parsing, processing, conversion, and output
- Plugin architecture allows extensibility

**RECOMMENDATION:** Excellent structure. No changes needed.

---

### 1.2 Dependency Management

**Dependencies Analysis (go.mod):**

```go
Core Framework:
- cobra v1.10.2         # CLI framework
- viper v1.21.0         # Configuration
- fang v0.4.4           # CLI enhancement

Formatting & Display:
- lipgloss v1.1.1       # Terminal styling
- glamour v0.10.0       # Markdown rendering
- log v0.4.2            # Structured logging

Data Processing:
- mxj v1.8.4            # XML processing
- validator v10.30.1    # Validation
- goldmark v1.7.16      # Markdown parsing
```

**ISSUES:**

1. **Charm library version spread** - Multiple versions of related libraries
2. **LRU cache** (`hashicorp/golang-lru/v2`) - Used but purpose unclear without deeper inspection

**RECOMMENDATION:**

- Consolidate Charm library versions to latest stable
- Document cache usage and tune size parameters

---

## 2. Architecture Patterns

### 2.1 Plugin Architecture (EXCELLENT)

**Design:**

```go
// Clean interface definition
type CompliancePlugin interface {
    Name() string
    Version() string
    Description() string
    RunChecks(device *common.CommonDevice) []Finding
    GetControls() []Control
    GetControlByID(id string) (*Control, error)
    ValidateConfiguration() error
}
```

**Strengths:**

- Loose coupling - only depends on `common.CommonDevice`
- Standardized `Finding` and `Control` structures
- Support for both built-in and dynamic (.so) plugins
- Thread-safe registry with `sync.RWMutex`
- Validation at registration time

**Example Usage:**

```go
// internal/audit/plugin.go
registry := NewPluginRegistry()
registry.RegisterPlugin(firewallPlugin)
registry.LoadDynamicPlugins(ctx, "/path/to/plugins", logger)
results := registry.RunComplianceChecks(device, []string{"firewall", "STIG"})
```

**RECOMMENDATION:** This is a **best practice example**. Consider documenting this as a reference architecture for other projects.

---

### 2.2 Parser Architecture (SECURE & EFFICIENT)

**Design:**

```go
type DeviceParser interface {
    Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, error)
    ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, error)
}
```

**Security Features:**

- **XML bomb protection** - 10MB default limit (`DefaultMaxInputSize`)
- **XXE attack prevention** - Empty entity map
- **Streaming processing** - Minimal memory footprint
- **Charset handling** - Safe fallbacks

**Implementation:**

```go
// Streaming approach for large files
limitedReader := io.LimitReader(r, p.MaxInputSize)
dec := xml.NewDecoder(limitedReader)
dec.CharsetReader = charsetReader
dec.Entity = map[string]string{}  // Prevent XXE
```

**STRENGTHS:**

- Security-first design
- Memory-efficient for large configs
- Clear error handling with context

**MINOR CONCERN:**

- Charset reader comment: "TODO: use golang.org/x/text/encoding"
- Currently treats ISO-8859-1 as UTF-8 (simplification)

**RECOMMENDATION:**

- Track the charset TODO in backlog
- For now, acceptable - most OPNsense configs are UTF-8

---

### 2.3 Converter Pattern (NEEDS CONSOLIDATION)

**ISSUE: Multiple Converter Implementations**

```
converter/
├── json.go              # JSONConverter (ToJSON with redaction support)
├── yaml.go              # YAMLConverter (ToYAML with redaction support)
├── markdown.go          # MarkdownConverter (ToMarkdown)
├── enrichment.go        # prepareForExport pipeline (Statistics, Analysis, etc.)
├── hybrid_generator.go  # HybridGenerator (StreamingGenerator interface)
├── builder/             # MarkdownBuilder (programmatic report generation)
│   ├── builder.go       # ReportBuilder interface
│   └── writer.go        # SectionWriter (io.Writer support)
└── formatters/          # Standalone formatting functions
    └── security.go      # CalculateSecurityScore, AssessRiskLevel

markdown/
├── generator.go         # markdownGenerator
└── validate.go          # Markdown validation (goldmark round-trip)
```

**Analysis:**

The converter package is the primary entry point for all format exports. The `prepareForExport()` enrichment pipeline in `enrichment.go` populates Statistics, Analysis, SecurityAssessment, and PerformanceMetrics before serialization. Format-specific converters (JSON, YAML, Markdown) each handle their own serialization.

**RECOMMENDATION:**

- Current structure is adequate — converters are format-specific with shared enrichment
- The `markdown/` package provides validation utilities used across formatters

---

### 2.4 Error Handling (COMPREHENSIVE)

**Strengths:**

```go
// Centralized error definitions
// internal/cfgparser/errors.go (290 lines)
var (
    ErrInvalidXML = errors.New("invalid XML")
    ErrMissingOpnSenseDocumentRoot = errors.New("invalid XML: missing opnsense root element")
    // ... comprehensive error catalog
)

// Wrapped errors with context
return fmt.Errorf("failed to parse configuration: %w", err)
```

**Error Files:**

- `cfgparser/errors.go` - Comprehensive error catalog
- `processor/errors.go` - Processing errors
- `compliance/errors.go` - Plugin errors (ErrPluginNotFound)

**Pattern:**

- Sentinel errors for expected conditions
- Wrapped errors with context
- Validation errors collected and aggregated

**RECOMMENDATION:**

- Excellent approach
- Consider error codes for machine-readable diagnostics (future enhancement)

---

### 2.5 Context Usage (INCONSISTENT)

**ISSUE: Underutilized Context**

```go
// Many functions accept but don't use context
func (c *MarkdownConverter) ToMarkdown(_ context.Context, data *common.CommonDevice) (string, error)
func (p *CoreProcessor) analyze(_ context.Context, cfg *common.CommonDevice, config *Config, report *Report)
```

**Analysis:**

- Context accepted for future cancellation support
- Currently not checked or propagated
- Named `_` to indicate intentional non-use

**CONCERN:**

- Long-running operations (analysis, large file parsing) cannot be cancelled
- No timeout support

**RECOMMENDATION:**

**Priority: Low-Medium**

1. **Add context checks to long-running operations:**

   ```go
   func (p *CoreProcessor) analyze(ctx context.Context, cfg *common.CommonDevice, config *Config, report *Report) {
       select {
       case <-ctx.Done():
           return ctx.Err()
       default:
       }

       // Continue processing...
   }
   ```

2. **Document context policy:**

   - When to check `ctx.Done()`
   - Timeout recommendations

---

## 3. Potential Architectural Issues

### 3.1 Global State (MODERATE CONCERN)

**Issue: Global Variables in Multiple Packages**

```go
// cmd/root.go
var (
    cfgFile string          // CLI config file path
    Cfg    *config.Config   // Application configuration
    logger *log.Logger      // Application logger
)

// internal/audit/plugin.go
var GlobalRegistry *PluginRegistry

func init() {
    GlobalRegistry = NewPluginRegistry()
}
```

**Impact:**

- **Testing complexity** - Global state requires careful setup/teardown
- **Concurrency risk** - Shared mutable state
- **Package coupling** - Implicit dependencies

**MITIGATION OBSERVED:**

- Plugin registry uses `sync.RWMutex` for thread safety
- CLI globals are acceptable for Cobra convention
- No evidence of mutation races

**RECOMMENDATION:**

**Priority: Medium**

1. **Refactor GlobalRegistry to dependency injection:**

   ```go
   // Before
   audit.RegisterGlobalPlugin(plugin)

   // After
   registry := audit.NewPluginRegistry()
   registry.RegisterPlugin(plugin)
   // Pass registry to processors that need it
   ```

2. **Keep CLI globals (acceptable for main package)**

3. **Add tests demonstrating thread safety**

---

### 3.2 Interface Count (LOW CONCERN)

**Finding:** 11 interface definitions across internal packages

**Analysis:**

- Appropriate for Go - favor small, focused interfaces
- Main interfaces:
  - `Parser` (2 methods)
  - `CompliancePlugin` (7 methods)
  - `Converter` (varied by format)
  - `Processor` (2-3 methods)

**RECOMMENDATION:**

- Current interface count is healthy
- No over-abstraction detected

---

### 3.3 Model Layer (ARCHITECTURAL STRENGTH)

**Design:**

```go
// internal/model/common/ - platform-agnostic device model
type CommonDevice struct {
    DeviceType string
    Version    string
    System     System
    Network    Network
    Firewall   Firewall
    // ... platform-agnostic device model
}
```

> **Note:** The OPNsense XML DTO (`schema.OpnSenseDocument`) remains in `internal/schema/opnsense.go` for XML parsing. The `ParserFactory` converts it to `CommonDevice` via `internal/model/opnsense/`.

**Strengths:**

- Platform-agnostic device model with OPNsense-specific parser
- Comprehensive XML/JSON/YAML tags
- Validation tags for go-playground/validator

**Potential Issue:**

- Large struct (multiple nested sub-structs in `CommonDevice`)
- Nested complexity

**MITIGATION:**

- Well-organized into logical sub-structs (System, Network, Security, Services)
- Clear domain separation

**RECOMMENDATION:**

- Current approach is appropriate for configuration modeling
- Monitor for excessive nesting depth (currently acceptable)

---

## 4. Scalability Considerations

### 4.1 Memory Efficiency (EXCELLENT)

**Streaming XML Parser:**

```go
// Processes XML tokens without loading full document
for {
    tok, err := dec.Token()
    if errors.Is(err, io.EOF) {
        break
    }
    // Process token...
}

// Garbage collection optimization
runtime.GC()
```

**Analysis:**

- 10MB default limit prevents XML bombs
- Streaming reduces memory footprint
- Explicit GC after large sections

**RECOMMENDATION:**

- Add configurable memory limits via config
- Document performance characteristics by file size

---

### 4.2 Concurrency (UNDERUTILIZED)

**Observation:**

- Plugin checks run sequentially
- Analysis phases run sequentially
- No obvious parallelization

**Potential Optimization:**

```go
// Current: Sequential
for _, pluginName := range pluginNames {
    findings := p.RunChecks(config)
    result.Findings = append(result.Findings, findings...)
}

// Potential: Parallel
var wg sync.WaitGroup
findingsChan := make(chan []plugin.Finding, len(pluginNames))

for _, pluginName := range pluginNames {
    wg.Add(1)
    go func(name string) {
        defer wg.Done()
        p := getPlugin(name)
        findingsChan <- p.RunChecks(config)
    }(pluginName)
}
```

**RECOMMENDATION:**

**Priority: Low** (Optimization, not architecture fix)

- Current approach is correct for typical config sizes
- Add parallel processing for large-scale batch operations
- Use worker pools to limit concurrency

---

### 4.3 Caching Strategy (UNCLEAR)

**Observation:**

- `hashicorp/golang-lru/v2` dependency
- No obvious cache usage in scanned files

**RECOMMENDATION:**

- Audit where LRU cache is used
- Document cache sizing and eviction policy
- Consider removing if unused

---

## 5. Maintainability and Modularity

### 5.1 Testing Structure (EXCELLENT)

**Coverage:**

- 61 test files
- Comprehensive test types:
  - Unit tests (`*_test.go`)
  - Benchmark tests (`*_bench_test.go`)
  - Integration tests (`*_integration_test.go`)

**Patterns Observed:**

```go
// Benchmark tests for performance tracking
func BenchmarkConvert(b *testing.B) { ... }

// Validation comprehensive tests
validation_comprehensive_test.go

// Legacy comparison tests
benchmark_legacy_test.go
```

**RECOMMENDATION:**

- Strong testing culture
- Add coverage reporting to CI
- Target >80% coverage (appears achievable)

---

### 5.2 Documentation (GOOD)

**Strengths:**

- Package-level documentation
- Function documentation follows godoc conventions
- Comprehensive README and docs/ folder

**Gaps:**

- Architecture diagrams would enhance understanding
- Plugin development guide needed
- Converter consolidation should be documented

**RECOMMENDATION:**

- Add architecture diagrams (mermaid)
- Document converter strategy and deprecation timeline
- Create plugin development guide

---

### 5.3 Code Organization (EXCELLENT)

**Patterns:**

- Clear separation of concerns
- Single Responsibility Principle followed
- No God objects detected
- Appropriate use of constructors (`New*`)

**Example:**

```go
// Clear factory pattern
func NewPluginRegistry() *PluginRegistry {
    return &PluginRegistry{
        plugins: make(map[string]plugin.CompliancePlugin),
    }
}
```

---

## 6. Security and Best Practices

### 6.1 Security Features (STRONG)

**XML Parsing:**

- XXE attack prevention
- XML bomb protection
- Size limits
- Entity expansion disabled

**Input Validation:**

- go-playground/validator integration
- Comprehensive validation rules
- Error aggregation

**RECOMMENDATION:**

- Document security features in security.md
- Add fuzzing tests for parser
- Consider static analysis integration (gosec)

---

### 6.2 Go Best Practices (MOSTLY FOLLOWED)

**Strengths:**

- Proper error wrapping (`fmt.Errorf("...: %w", err)`)
- Context propagation
- Interface segregation
- Clear package boundaries

**Minor Issues:**

- Some `//nolint` directives (acceptable with justification)
- Global variables (discussed above)
- Context underutilization (discussed above)

---

## 7. Recommendations Summary

### 7.1 High Priority (Architectural)

1. **Consolidate Converter Pattern**

   - **Effort:** Medium
   - **Impact:** High (reduces confusion, improves maintainability)
   - **Action:** Create unified converter interface

2. **Reduce Global State**

   - **Effort:** Low-Medium
   - **Impact:** Medium (improves testability, reduces coupling)
   - **Action:** Inject PluginRegistry instead of using global

### 7.2 Medium Priority (Quality)

3. **Improve Context Usage**

   - **Effort:** Low
   - **Impact:** Medium (enables cancellation, timeouts)
   - **Action:** Add context checks to long-running operations

### 7.3 Low Priority (Enhancement)

5. **Add Architecture Diagrams**

   - **Effort:** Low
   - **Impact:** High (documentation quality)
   - **Action:** Create mermaid diagrams for data flow, plugin architecture

6. **Optimize Parallelization**

   - **Effort:** Medium
   - **Impact:** Low (performance optimization)
   - **Action:** Add concurrent plugin execution for large-scale ops

7. **Audit Cache Usage**

   - **Effort:** Low
   - **Impact:** Low (code clarity)
   - **Action:** Find or remove LRU cache dependency

---

## 8. Areas Following Best Practices

### 8.1 Exceptional Examples

**Plugin Architecture:**

- Clean interfaces
- Thread-safe registry
- Extensible design
- Standardized data structures

**Parser Security:**

- Defense in depth
- Resource limits
- Streaming processing
- Clear error handling

**Testing Strategy:**

- Comprehensive coverage
- Benchmarks for performance tracking
- Integration and unit tests
- Legacy comparison tests

### 8.2 Modern Go Patterns

- Functional options pattern (processor options)
- Context propagation
- Error wrapping with `%w`
- Interface-based design
- Constructor functions

---

## 9. Technical Debt Tracking

### 9.1 Known Issues

1. **Charset Reader TODO**

   - Location: `cfgparser/xml.go`
   - Impact: Limited encoding support
   - Workaround: Most configs are UTF-8

2. **Context Underutilization**

   - Locations: Multiple functions
   - Impact: No cancellation support
   - Risk: Low for current use cases

---

## 10. Conclusion

### 10.1 Overall Assessment

opnDossier demonstrates **mature software architecture** with:

- Strong separation of concerns
- Extensible plugin system
- Secure-by-default XML parsing
- Comprehensive testing
- Modern Go idioms

### 10.2 Key Strengths

1. Plugin architecture (best practice)
2. Security-first parser design
3. Clean package organization
4. Comprehensive error handling
5. Strong testing culture

### 10.3 Key Improvement Areas

1. Consolidate converter pattern
2. Reduce global state
3. Improve context usage

### 10.4 Recommendation

**No major architectural changes required.** The codebase is well-designed for long-term maintainability. Focus on:

- **Short term:** Consolidate converters
- **Medium term:** Improve context usage, reduce globals
- **Long term:** Add architecture diagrams, performance optimization

**The simplest approach that will work for the long term:** Continue current architecture, execute tactical improvements from recommendations above.

---

**Review Status:** Complete **Next Review:** After converter consolidation (Q2 2026)
