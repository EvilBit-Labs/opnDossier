# AI Agent Coding Standards and Project Structure

This document consolidates all development standards, architectural principles, and workflows for the opnDossier project.

## Related Documentation

- **[Requirements](../project_spec/requirements.md)** - Complete project requirements and specifications
- **[Architecture](architecture.md)** - System design, component interactions, and deployment patterns
- **[Development Standards](standards.md)** - Go-specific coding standards and project structure

---

## 1. Rule Precedence

**CRITICAL - Rules are applied in the following order:**

1. **Project-specific rules** (this document, .cursor/rules/)
2. **General development standards** (docs/development/standards.md)
3. **Language-specific style guides** (Go conventions)

When rules conflict, follow the higher precedence rule.

---

## 2. Core Philosophy

| Principle            | Description                                                                         |
| -------------------- | ----------------------------------------------------------------------------------- |
| **Operator-Focused** | Build tools for operators, by operators. Intuitive and efficient workflows          |
| **Offline-First**    | Operate in fully offline/airgapped environments. No external dependencies           |
| **Structured Data**  | Data should be structured, versioned, and portable for auditable systems            |
| **Framework-First**  | Leverage established frameworks. Avoid custom solutions when established ones exist |

### EvilBit Labs Brand Principles

- **Trust the Operator:** Full control, no black boxes
- **Polish Over Scale:** Quality over feature-bloat
- **Offline First:** Built for where the internet isn't
- **Sane Defaults:** Clean outputs, CLI help that's actually helpful
- **Ethical Constraints:** No dark patterns, spyware, or telemetry

---

## 3. Technology Stack

| Layer              | Technology                                             |
| ------------------ | ------------------------------------------------------ |
| CLI Framework      | `cobra` v1.8.0                                         |
| CLI Enhancement    | `charmbracelet/fang` for styled help, errors, features |
| Configuration      | `spf13/viper` for config parsing                       |
| Terminal Styling   | `charmbracelet/lipgloss`                               |
| Markdown Rendering | `charmbracelet/glamour`                                |
| Logging            | `charmbracelet/log`                                    |
| Data Formats       | `encoding/xml`, `encoding/json`, `gopkg.in/yaml.v3`    |
| Testing            | Go's built-in `testing` package                        |

**Go Version:** 1.21.6+ (minimum), 1.24.5+ (recommended)

> [!NOTE]
> `viper` manages opnDossier's own configuration (CLI settings, display preferences), not OPNsense config.xml parsing. XML parsing is handled by `internal/parser/`.

---

## 4. Project Structure

```text
opndossier/
├── cmd/                              # CLI command entry points
│   ├── root.go                       # Root command
│   ├── convert.go                    # Convert command
│   ├── display.go                    # Display command
│   └── validate.go                   # Validate command
├── internal/                         # Private application logic
│   ├── audit/                        # Audit engine and compliance checking
│   │   ├── plugin.go                 # Plugin registry
│   │   └── plugin_manager.go         # Plugin lifecycle
│   ├── config/                       # Configuration management
│   ├── converter/                    # Data conversion utilities
│   ├── display/                      # Terminal display formatting
│   ├── export/                       # File export functionality
│   ├── log/                          # Logging utilities
│   ├── markdown/                     # Markdown generation
│   ├── model/                        # Data models and structures
│   ├── parser/                       # XML parsing and validation
│   ├── plugin/                       # Plugin interfaces
│   ├── plugins/                      # Compliance plugins
│   │   ├── firewall/                 # Firewall compliance
│   │   ├── sans/                     # SANS compliance
│   │   └── stig/                     # STIG compliance
│   ├── processor/                    # Data processing and report generation
│   └── validator/                    # Data validation
├── pkg/                              # Public packages (if any)
├── testdata/                         # Test data and fixtures
├── docs/                             # Documentation
├── project_spec/                     # Project specifications
│   ├── requirements.md               # Requirements specification
│   ├── tasks.md                      # Implementation tasks
│   └── user_stories.md               # User stories
├── go.mod / go.sum                   # Go modules
├── justfile                          # Task runner
└── main.go                           # Entry point
```

---

## 5. Go Development Standards

### 5.1 Naming Conventions

| Element             | Convention                                 | Example                     |
| ------------------- | ------------------------------------------ | --------------------------- |
| Packages            | lowercase, single word                     | `parser`, `config`          |
| Variables/functions | camelCase (private), PascalCase (exported) | `configFile`, `ParseConfig` |
| Types               | PascalCase                                 | `ConfigParser`              |
| Constants           | PascalCase (avoid ALL_CAPS)                | `DefaultTimeout`            |
| Receivers           | single letter                              | `func (c *Config)`          |
| Interfaces          | PascalCase, `-er` suffix when appropriate  | `ConfigReader`              |

### 5.2 Error Handling

```go
// Always wrap errors with context using %w
if err := validateConfig(config); err != nil {
return nil, fmt.Errorf("config validation failed: %w", err)
}

// Use errors.Is() and errors.As() for checking
var parseErr *ParseError
if errors.As(err, &parseErr) {
// Handle parse-specific error
}

// Create domain-specific error types
type ParseError struct {
Message string
Line    int
}

func (e *ParseError) Error() string {
return fmt.Sprintf("parse error at line %d: %s", e.Line, e.Message)
}
```

### 5.3 Logging

Use `charmbracelet/log` for structured logging:

```go
logger := log.With("input_file", config.InputFile)
logger.Info("starting processing")
logger.Error("validation failed", "error", err)
```

Log levels: `debug` (troubleshooting), `info` (operations), `warn` (issues), `error` (failures)

### 5.4 Documentation

```go
// Package parser provides functionality for parsing OPNsense configuration files.
package parser

// ParseConfig reads and parses an OPNsense configuration file.
// It returns a structured representation or an error if parsing fails.
func ParseConfig(filename string) (*Config, error) {
  // implementation
}
```

- Start comments with the name of the thing being described
- Use complete sentences
- Include examples for complex functionality

### 5.5 Import Organization

```go
import (
// Standard library
"fmt"
"os"

// Third-party
"github.com/spf13/cobra"

// Internal
"github.com/project/internal/parser"
)
```

### 5.6 Thread Safety

When using `sync.RWMutex` to protect struct fields:

- ALL read methods need `RLock()`, not just write methods
- Go's `sync.RWMutex` is NOT reentrant - create internal `*Unsafe()` helpers
- Example pattern from `internal/processor/report.go`:

```go
func (r *Report) TotalFindings() int {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.totalFindingsUnsafe()  // Internal helper, no lock
}
```

---

## 6. Data Processing Standards

### 6.1 Data Models

- **OpnSenseDocument**: Core data model representing entire OPNsense configuration
- **XML Tags**: Must strictly follow OPNsense configuration file structure
- **JSON/YAML Tags**: Follow recommended best practices for each format
- **Audit Models**: Create separate structs (`Finding`, `Target`, `Exposure`) for audit concepts

### 6.2 Multi-Format Export

```bash
opndossier convert config.xml --format [markdown|json|yaml]
opndossier convert config.xml --format json -o output.json
opndossier convert config.xml --format yaml --force
```

- Exported files must be valid and parseable by standard tools
- Smart file naming with overwrite protection (`-f` to force)

### 6.3 Report Generation

| Mode            | Audience   | Focus                                 |
| --------------- | ---------- | ------------------------------------- |
| Standard (ops)  | Operations | General configuration overview        |
| Blue (defense)  | Blue Team  | Clarity, grouping, actionability      |
| Red (adversary) | Red Team   | Target prioritization, pivot surfaces |

All report generation uses programmatic Go code via `builder.MarkdownBuilder` (no template system).

### 6.4 Modular Report Generator Architecture

Each report generator should be a **self-contained Go module** that can be included or excluded via build flags. This architecture enables Pro-level features and independent development of report types.

**What Each Report Module Should Contain:**

- All generation logic (markdown construction, section building)
- All calculation logic (security scoring, risk assessment, statistics)
- All data transformations specific to that report type
- Report-specific constants and mappings

**What Should Remain Shared:**

- `model.OpnSenseDocument` - The parsed configuration model
- Shared helpers (string formatting, markdown escaping, table building)
- Common interfaces (`ReportBuilder`, `Generator`)

**Build Flag Integration:**

```go
//go:build pro

package reports

// Pro-level report generators included only with -tags=pro
```

**Implementation Pattern:**

```go
// Each report module is self-contained
type BlueTeamGenerator struct {
    // All state for blue team reports
}

func (g *BlueTeamGenerator) Generate(doc *model.OpnSenseDocument) (string, error) {
    // Uses only model and shared helpers
    // All calculations are internal to this module
    score := g.calculateSecurityScore(doc)  // Internal method
    findings := g.analyzeCompliance(doc)    // Internal method
    return g.buildReport(doc, score, findings)
}
```

See [Architecture Documentation](docs/development/architecture.md#modular-report-generator-architecture) for detailed design.

---

## 7. Testing Standards

### 7.1 Test Organization

```go
func TestParseConfig_ValidXML_ReturnsConfig(t *testing.T) {
tests := []struct {
name    string
input   string
want    *Config
wantErr bool
}{
{
name:    "valid config",
input:   "<opnsense>...</opnsense>",
want:    &Config{},
wantErr: false,
},
}

for _, tt := range tests {
t.Run(tt.name, func (t *testing.T) {
got, err := ParseConfig(tt.input)
if (err != nil) != tt.wantErr {
t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
}
})
}
}
```

### 7.2 Test Requirements

| Requirement       | Target                       |
| ----------------- | ---------------------------- |
| Coverage          | >80%                         |
| Speed             | \<100ms per test             |
| Race detection    | `go test -race`              |
| Integration tests | `//go:build integration` tag |

### 7.3 Test Helpers

```go
func setupTestConfig(t *testing.T) *Config {
t.Helper()
return &Config{InputFile: "testdata/config.xml"}
}

func createTempFile(t *testing.T, content string) string {
t.Helper()
// implementation with t.Cleanup()
}
```

---

## 8. Plugin Architecture

### 8.1 Core Components

| File                               | Purpose                                                    |
| ---------------------------------- | ---------------------------------------------------------- |
| `internal/plugin/interfaces.go`    | `CompliancePlugin` interface, `Control`, `Finding` structs |
| `internal/audit/plugin.go`         | `PluginRegistry`, dynamic plugin loader                    |
| `internal/audit/plugin_manager.go` | `PluginManager` for lifecycle operations                   |
| `internal/plugins/`                | Built-in plugin implementations                            |

### 8.2 Plugin Interface

All plugins must implement `CompliancePlugin`:

```go
type CompliancePlugin interface {
Name() string
Version() string
Description() string
RunChecks(config *model.OpnSenseDocument) []Finding
GetControls() []Control
GetControlByID(id string) (*Control, error)
ValidateConfiguration() error
}
```

### 8.3 Plugin Development

```go
type Plugin struct {
controls []plugin.Control
}

func NewPlugin() *Plugin {
return &Plugin{controls: initControls()}
}

func (p *Plugin) RunChecks(config *model.OpnSenseDocument) []plugin.Finding {
// Implement compliance checks
}
```

- Use consistent control naming: `PLUGIN-001`, `PLUGIN-002`
- Severity levels: `critical`, `high`, `medium`, `low`
- Dynamic plugins: export `var Plugin plugin.CompliancePlugin`

### 8.4 Compliance Standards

| Standard | Control Pattern | Location                     |
| -------- | --------------- | ---------------------------- |
| STIG     | `STIG-V-XXXXXX` | `internal/plugins/stig/`     |
| SANS     | `SANS-XXX`      | `internal/plugins/sans/`     |
| Firewall | `FIREWALL-XXX`  | `internal/plugins/firewall/` |

---

## 9. Commit Style

### 9.1 Conventional Commits

```text
<type>(<scope>): <description>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`

**Scopes:** `(parser)`, `(converter)`, `(audit)`, `(cli)`, `(model)`, `(plugin)`, `(builder)`

### 9.2 Examples

```text
feat(parser): add support for OPNsense 24.1 config format
fix(converter): handle empty VLAN configurations gracefully
docs(readme): update installation instructions
feat(api)!: redesign plugin interface  # Breaking change
```

### 9.3 Rules

- Imperative mood ("add", not "added")
- No period at the end
- ≤72 characters, capitalized
- **Scope is required**
- Breaking changes: add `!` or use `BREAKING CHANGE:` in footer

---

## 10. Development Workflow

### 10.1 Command Reference

```bash
# Development
just dev              # Run in development mode
just build            # Build with all checks
just install          # Install dependencies

# Quality
just format           # Format code and docs
just lint             # Run linting
just test             # Run tests
just check            # Run pre-commit hooks
just ci-check         # Run CI-equivalent checks

# Go commands
go test ./...         # Run tests
go test -race ./...   # Race detection
go test -cover ./...  # Coverage
go mod tidy           # Clean dependencies
go mod verify         # Verify dependencies
```

### 10.2 Secure Build

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o opnDossier ./main.go
```

- `-trimpath`: Remove local paths from binaries
- `-ldflags="-s -w"`: Strip debug info
- `CGO_ENABLED=0`: Static, portable builds

---

## 11. Security Standards

| Principle              | Implementation                                  |
| ---------------------- | ----------------------------------------------- |
| No secrets in code     | Use environment variables or secure vaults      |
| Input validation       | Validate and sanitize all user inputs           |
| Secure defaults        | Default to secure configurations                |
| File permissions       | Use 0600 for config files                       |
| Error messages         | Avoid exposing sensitive information            |
| Network unavailability | Cache reference data locally, handle gracefully |

---

## 12. AI Agent Guidelines

### 12.1 Mandatory Practices

01. **Always run tests** after changes: `just test`
02. **Run linting** before committing: `just lint`
03. **Follow established patterns** in existing code
04. **Write comprehensive tests** for new functionality
05. **Include proper error handling** with context
06. **Add structured logging** for important operations
07. **Validate all inputs** and handle edge cases
08. **Document new functions and types** following Go conventions
09. **Never commit secrets** or hardcoded credentials
10. **Consult project documentation** before making changes
11. Prefer structured config data + audit overlays over flat summary tables
12. Validate markdown with `mdformat` and `markdownlint-cli2`
13. **CRITICAL: Tasks are NOT complete until `just ci-check` passes**
14. Place `//nolint:` directives on SEPARATE LINE above call (inline gets stripped by gofumpt)

### 12.2 Code Review Checklist

- [ ] Code follows Go formatting (`gofmt`)
- [ ] Linting issues resolved (`golangci-lint`)
- [ ] Tests pass (`go test ./...`)
- [ ] Error handling includes context
- [ ] Structured logging used appropriately
- [ ] No hardcoded secrets
- [ ] Input validation implemented
- [ ] Documentation updated
- [ ] Dependencies managed (`go mod tidy`)
- [ ] Follows established patterns
- [ ] Requirements compliance verified
- [ ] Architecture patterns followed

### 12.3 Rules of Engagement

- **TERM=dumb Support**: Ensure terminal output respects `TERM="dumb"` for CI/automation
- **No Auto-commits**: Never commit without explicit permission
- **Focus on Value**: Enhance the project's unique value as an OPNsense auditing tool
- **No Destructive Actions**: No major refactors without explicit permission
- **Stay Focused**: Avoid scope creep

### 12.4 Issue Resolution

When encountering problems:

1. Identify the specific issue clearly
2. Explain the problem in ≤5 lines
3. Propose a concrete path forward
4. Don't proceed without resolving blockers

---

## 13. Documentation Standards

### 13.1 Writing Style

- **Concise**: Prefer clear explanations over verbose descriptions
- **Consistent**: Maintain consistent style across all files
- **Clear**: Use direct language that avoids ambiguity

### 13.2 Formatting

- Standard markdown formatting
- Consistent heading hierarchy (H1 → H2 → H3)
- Proper syntax highlighting for code blocks
- Descriptive link text

### 13.3 Validation

```bash
just format                     # Format markdown
markdownlint **/*.md           # Validate syntax
just ci-check                  # Comprehensive checks
```

---

## 14. Requirements Management

### 14.1 Document Relationships

| Document          | Purpose                          |
| ----------------- | -------------------------------- |
| `requirements.md` | WHAT the system must do          |
| `tasks.md`        | HOW to implement requirements    |
| `user_stories.md` | WHY requirements matter to users |

### 14.2 Task Structure

```markdown
- [ ] **TASK-###**: Task Title
  - **Context**: Why this task is needed
  - **Requirement**: F###
  - **User Story**: US-###
  - **Action**: Implementation steps
  - **Acceptance**: Completion criteria
```

### 14.3 Task States

| Symbol | State       |
| ------ | ----------- |
| `[ ]`  | Not started |
| `[-]`  | In progress |
| `[x]`  | Completed   |

---

## 15. CLI Usage Examples

```bash
# Convert configurations
./opndossier convert config.xml --format markdown
./opndossier convert config.xml --format json -o output.json
./opndossier convert config.xml --format yaml --force

# Display configuration
./opndossier display config.xml

# Validate configuration
./opndossier validate config.xml
```
