# API Reference

This document provides detailed information about the opnDossier internal Go API and its components.

## Overview

opnDossier is structured with clear separation between CLI interface (`cmd/`) and internal implementation (`internal/`). All packages under `internal/` are private to the module and not importable by external consumers.

## Package Structure

```text
opndossier/
├── cmd/                         # CLI commands (Cobra framework)
│   ├── root.go                  # Root command, global flags, version subcommand
│   ├── context.go               # CommandContext for dependency injection
│   ├── convert.go               # Convert command
│   ├── display.go               # Display command
│   ├── validate.go              # Validate command
│   ├── shared_flags.go          # Shared flags (section, wrap, audit)
│   ├── exitcodes.go             # Structured exit codes
│   └── help.go                  # Custom help templates
├── internal/
│   ├── analysis/                # Canonical finding and severity types
│   ├── cfgparser/               # XML parsing and validation
│   ├── config/                  # Configuration management (Viper)
│   ├── converter/               # Data conversion and report generation
│   │   ├── builder/             # Programmatic markdown builder
│   │   └── formatters/          # Security scoring, transformers
│   ├── schema/                  # Canonical data model structs
│   ├── model/                   # Re-export layer (type aliases)
│   ├── compliance/              # Plugin interfaces
│   ├── plugins/                 # Plugin implementations (stig, sans, firewall)
│   ├── audit/                   # Audit engine and plugin management
│   ├── display/                 # Terminal display formatting
│   ├── export/                  # File export functionality
│   ├── logging/                 # Structured logging (charmbracelet/log)
│   ├── progress/                # CLI progress indicators
│   ├── processor/               # Security analysis and report generation
│   └── validator/               # Configuration validation
└── main.go                      # Entry point
```

## CLI Package (cmd/)

### Root Command

```go
// GetRootCmd returns the root Cobra command
func GetRootCmd() *cobra.Command
```

### CommandContext Pattern

The `cmd` package uses `CommandContext` for dependency injection into subcommands:

```go
type CommandContext struct {
    Config *config.Config
    Logger *logging.Logger
}

// Access in subcommands:
cmdCtx := GetCommandContext(cmd)
logger := cmdCtx.Logger
config := cmdCtx.Config
```

### Global Flags

| Flag            | Type   | Default  | Description                        |
| --------------- | ------ | -------- | ---------------------------------- |
| `--config`      | string | `""`     | Custom config file path            |
| `--verbose, -v` | bool   | false    | Enable debug logging               |
| `--quiet, -q`   | bool   | false    | Suppress non-error output          |
| `--color`       | string | `"auto"` | Color output (auto, always, never) |
| `--no-progress` | bool   | false    | Disable progress indicators        |
| `--timestamps`  | bool   | false    | Include timestamps in logs         |
| `--minimal`     | bool   | false    | Minimal output mode                |
| `--json-output` | bool   | false    | Output errors in JSON format       |

## Parser Package (internal/cfgparser)

### DeviceParser Interface

The `DeviceParser` interface (defined in `internal/model/factory.go`) abstracts device-specific parsing behind a common contract:

```go
type DeviceParser interface {
    // Parse reads and converts the configuration, returning non-fatal conversion warnings.
    Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error)
    // ParseAndValidate reads, converts, and validates the configuration, returning non-fatal conversion warnings.
    ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error)
}
```

**Breaking Change:** Both methods return a 3-value tuple `(*CommonDevice, []ConversionWarning, error)` instead of the previous 2-value return `(*CommonDevice, error)`. Implementations must return non-fatal conversion warnings alongside the parsed device model. Callers should log or surface these warnings without treating them as errors.

The `ParserFactory` auto-detects device type from the XML root element and delegates to the appropriate `DeviceParser`. The underlying OPNsense XML parser (`internal/cfgparser/XMLParser`) still produces `schema.OpnSenseDocument`, which is then converted to `common.CommonDevice` by the OPNsense-specific parser in `internal/model/opnsense/`.

### ParserFactory Usage

```go
factory := model.NewParserFactory()

file, err := os.Open("config.xml")
if err != nil {
    return err
}
defer file.Close()

// Auto-detect device type and parse to CommonDevice
device, warnings, err := factory.CreateDevice(context.Background(), file, "", false)
if err != nil {
    return fmt.Errorf("parse failed: %w", err)
}
// Handle warnings (e.g., log them)
for _, w := range warnings {
    logger.Warn("conversion warning", "field", w.Field, "message", w.Message)
}

// With validation
device, warnings, err := factory.CreateDevice(context.Background(), file, "", true)
if err != nil {
    return fmt.Errorf("parse and validate failed: %w", err)
}
```

**Breaking Change:** `CreateDevice` returns a 3-value tuple `(*CommonDevice, []ConversionWarning, error)` instead of the previous 2-value return `(*CommonDevice, error)`. Warnings represent non-fatal conversion issues that should be logged but do not prevent successful parsing.

The underlying `XMLParser` (`internal/cfgparser/`) supports UTF-8, US-ASCII, ISO-8859-1 (Latin1), and Windows-1252 encodings. Input is limited to 10MB by default (`DefaultMaxInputSize`).

## Data Model (internal/schema, internal/model)

### CommonDevice

The platform-agnostic device model, defined in `internal/model/common/`:

```go
type CommonDevice struct {
    DeviceType DeviceType      `json:"device_type" yaml:"device_type"`
    Version    string          `json:"version,omitempty" yaml:"version,omitempty"`
    System     System          `json:"system" yaml:"system,omitempty"`
    Interfaces []Interface     `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
    FirewallRules []FirewallRule `json:"firewallRules,omitempty" yaml:"firewallRules,omitempty"`
    NAT        NATConfig       `json:"nat" yaml:"nat,omitempty"`
    VPN        VPN             `json:"vpn" yaml:"vpn,omitempty"`
    Routing    Routing         `json:"routing" yaml:"routing,omitempty"`
    DNS        DNSConfig       `json:"dns" yaml:"dns,omitempty"`
    DHCP       []DHCPScope     `json:"dhcp,omitempty" yaml:"dhcp,omitempty"`
    // ... additional fields (Users, Groups, Certificates, etc.)

    // Computed/enrichment fields (populated by prepareForExport)
    Statistics         *Statistics         `json:"statistics,omitempty"`
    SecurityAssessment *SecurityAssessment `json:"securityAssessment,omitempty"`
    // ...
}
```

The XML DTO remains as `schema.OpnSenseDocument` in `internal/schema/opnsense.go`. The OPNsense-specific parser in `internal/model/opnsense/` converts the XML DTO into `CommonDevice`. The `internal/model/` package provides the `ParserFactory` and `DeviceParser` interface for consumers.

### ConversionWarning

The `ConversionWarning` type represents non-fatal issues encountered during conversion from a platform-specific schema to the platform-agnostic `CommonDevice` model:

```go
type ConversionWarning struct {
    // Field is the dot-path of the problematic field (e.g., "FirewallRules[0].Type").
    Field string
    // Value provides context to identify the affected config element (e.g., rule UUID,
    // gateway name, or certificate description). When the warning is about a missing or
    // empty field, this contains a sibling identifier rather than the empty field itself.
    Value string
    // Message is a human-readable description of the issue.
    Message string
    // Severity indicates the importance of the warning.
    Severity analysis.Severity
}
```

**When Warnings Are Generated:**

Warnings are returned for non-fatal conversion issues such as:

- Missing or empty required fields in firewall rules (type, source, destination, interface)
- NAT rules missing internal IP or interface assignments
- Gateways missing address or name fields
- Users missing name or UID fields

**Handling Warnings:**

Callers should log warnings using structured logging but continue processing:

```go
device, warnings, err := parser.Parse(ctx, reader)
if err != nil {
    return fmt.Errorf("parse failed: %w", err)
}
for _, w := range warnings {
    logger.Warn("conversion issue", 
        "field", w.Field, 
        "value", w.Value, 
        "message", w.Message, 
        "severity", w.Severity)
}
// Continue with device processing
```

Warnings differ from errors in that they indicate data quality issues or missing optional fields that do not prevent successful conversion. The converted `CommonDevice` is still valid and usable, but may contain incomplete information from the source configuration.

## Converter Package (internal/converter)

### Converter Interface

```go
type Converter interface {
    ToMarkdown(ctx context.Context, data *common.CommonDevice) (string, error)
}
```

### Generator Interface

```go
type Generator interface {
    Generate(ctx context.Context, cfg *common.CommonDevice, opts Options) (string, error)
}

type StreamingGenerator interface {
    Generator
    GenerateToWriter(ctx context.Context, w io.Writer, cfg *common.CommonDevice, opts Options) error
}
```

### MarkdownBuilder (internal/converter/builder)

The `MarkdownBuilder` provides programmatic report generation:

```go
builder := builder.NewMarkdownBuilder()

// Generate a standard report
report, err := builder.BuildStandardReport(doc)

// Generate a comprehensive report
report, err := builder.BuildComprehensiveReport(doc)

// Build individual sections
systemSection := builder.BuildSystemSection(doc)
networkSection := builder.BuildNetworkSection(doc)
securitySection := builder.BuildSecuritySection(doc)
servicesSection := builder.BuildServicesSection(doc)
```

### Security Functions (internal/converter/formatters)

```go
// Standalone security assessment functions
formatters.AssessRiskLevel("high")           // Returns: "🟠 High Risk"
formatters.CalculateSecurityScore(doc)       // Returns: 0-100
formatters.AssessServiceRisk("telnet")       // Returns: risk label string
formatters.FilterSystemTunables(items, true) // Filter security-related tunables
formatters.GroupServicesByStatus(services)   // Group by running/stopped
```

## Configuration Package (internal/config)

### Config Type

```go
type Config struct {
    InputFile   string   `mapstructure:"input_file"`
    OutputFile  string   `mapstructure:"output_file"`
    Verbose     bool     `mapstructure:"verbose"`
    Quiet       bool     `mapstructure:"quiet"`
    Theme       string   `mapstructure:"theme"`
    Format      string   `mapstructure:"format"`
    Sections    []string `mapstructure:"sections"`
    WrapWidth   int      `mapstructure:"wrap"`
    JSONOutput  bool     `mapstructure:"json_output"`
    Minimal     bool     `mapstructure:"minimal"`
    NoProgress  bool     `mapstructure:"no_progress"`
    // ... additional fields
}
```

### Loading Configuration

```go
// Load with default config file location
cfg, err := config.LoadConfig("")

// Load with CLI flag binding
cfg, err := config.LoadConfigWithFlags(configFile, cmd.Flags())

// Load with custom Viper instance
cfg, err := config.LoadConfigWithViper(configFile, v)
```

### Configuration Precedence

1. **CLI Flags** (highest priority)
2. **Environment Variables** (`OPNDOSSIER_*`)
3. **Configuration File** (`~/.opnDossier.yaml`)
4. **Default Values** (lowest priority)

## Export Package (internal/export)

### FileExporter

```go
type FileExporter struct {
    // ...
}

func NewFileExporter(logger *logging.Logger) *FileExporter

// Export writes content to a file with path validation and atomic writes
func (e *FileExporter) Export(ctx context.Context, content, path string) error
```

Features: path traversal protection, atomic writes, platform-appropriate permissions (0600 default).

## Logging Package (internal/logging)

### Logger

Wraps `charmbracelet/log` for structured logging:

```go
logger, err := logging.New(logging.Config{
    Level:           "info",
    Format:          "text",
    Output:          os.Stderr,
    ReportCaller:    true,
    ReportTimestamp: true,
})

logger.Info("Processing file", "filename", path, "size", fileSize)
logger.Debug("Detailed info", "key", value)
logger.Warn("Potential issue", "error", err)
logger.Error("Operation failed", "error", err)

// Create scoped loggers
fileLogger := logger.WithFields("operation", "convert", "file", filename)
```

## Analysis Package (internal/analysis)

The `internal/analysis` package provides canonical types for security analysis findings shared across the audit, compliance, and processor packages. This ensures consistent finding representation throughout the codebase.

### Finding Type

```go
type Finding struct {
    // Type categorizes the finding (e.g., "security", "performance", "compliance")
    Type string `json:"type"`
    // Severity indicates the severity level of the finding
    Severity string `json:"severity,omitempty"`
    // Title is a brief description of the finding
    Title string `json:"title"`
    // Description provides detailed information about the finding
    Description string `json:"description"`
    // Recommendation suggests how to address the finding
    Recommendation string `json:"recommendation"`
    // Component identifies the configuration component involved
    Component string `json:"component"`
    // Reference provides additional information or documentation links
    Reference string `json:"reference"`

    // Generic references and metadata
    // References contains related standard or control identifiers
    References []string `json:"references,omitempty"`
    // Tags contains classification labels for the finding
    Tags []string `json:"tags,omitempty"`
    // Metadata contains arbitrary key-value pairs for additional context
    Metadata map[string]string `json:"metadata,omitempty"`
}
```

**JSON Tag Note:** The `Recommendation`, `Component`, and `Reference` fields intentionally lack `omitempty` to maintain consistency with the original `compliance.Finding` conventions.

### Severity Type

```go
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)
```

**Helper Functions:**

```go
// ValidSeverities returns a fresh copy of all valid severity values
func ValidSeverities() []Severity

// IsValidSeverity checks whether the given severity is a recognized value
func IsValidSeverity(s Severity) bool

// String returns the string representation of the severity
func (s Severity) String() string
```

## Compliance Package (internal/compliance)

### Plugin Interface

```go
type Plugin interface {
    Name() string
    Version() string
    Description() string
    RunChecks(device *common.CommonDevice) []Finding
    GetControls() []Control
    GetControlByID(id string) (*Control, error)
    ValidateConfiguration() error
}
```

### Finding Type

The `compliance.Finding` type is a type alias for the canonical `analysis.Finding` defined in the `internal/analysis` package. All compliance plugins and consumers use this standardized finding structure.

```go
// Finding is a type alias for the canonical analysis.Finding type
type Finding = analysis.Finding
```

See the [Analysis Package](#analysis-package-internalanalysis) section for the complete struct definition and field descriptions.

**Severity Handling:**

Plugins must set `Finding.Severity` from control metadata using the control's severity field. The audit engine (`internal/audit/plugin.go`) validates that all findings have severity populated, deriving it from referenced controls if not set. If a finding references a control that cannot be resolved or has no severity, the audit engine returns an error.

See [Plugin Development Guide](plugin-development.md) for details.

### Audit Package Types (internal/audit)

#### ComplianceResult

The `ComplianceResult` struct represents the complete result of compliance checks:

```go
type ComplianceResult struct {
    Findings       []compliance.Finding            `json:"findings"`
    PluginFindings map[string][]compliance.Finding `json:"pluginFindings"`
    Compliance     map[string]map[string]bool      `json:"compliance"`
    Summary        *ComplianceSummary              `json:"summary"`
    PluginInfo     map[string]PluginInfo           `json:"pluginInfo"`
}
```

**Fields:**

- `Findings` ([]compliance.Finding): Aggregated findings from all plugins
- `PluginFindings` (map[string][]compliance.Finding): Findings grouped by plugin name
- `Compliance` (map[string]map[string]bool): Compliance status per plugin per control
- `Summary` (`*ComplianceSummary`): Summary statistics with severity breakdown
- `PluginInfo` (map[string]PluginInfo): Metadata about executed plugins

#### ComplianceSummary

The `ComplianceSummary` struct provides summary statistics with severity breakdown:

```go
type ComplianceSummary struct {
    TotalFindings    int                            `json:"totalFindings"`
    CriticalFindings int                            `json:"criticalFindings"`
    HighFindings     int                            `json:"highFindings"`
    MediumFindings   int                            `json:"mediumFindings"`
    LowFindings      int                            `json:"lowFindings"`
    PluginCount      int                            `json:"pluginCount"`
    Compliance       map[string]PluginCompliance    `json:"compliance"`
}
```

**Fields:**

- `TotalFindings` (int): Total number of findings
- `CriticalFindings` (int): Count of critical severity findings
- `HighFindings` (int): Count of high severity findings
- `MediumFindings` (int): Count of medium severity findings
- `LowFindings` (int): Count of low severity findings
- `PluginCount` (int): Number of plugins executed
- `Compliance` (map[string]PluginCompliance): Per-plugin compliance status

**Report Behavior:**

Blue team reports generated by the audit engine include per-plugin severity breakdowns in addition to aggregate summaries. Each plugin's findings are stored separately in the `ComplianceResult` structure, allowing reports to display both overall statistics and plugin-specific details.

## Processor Package (internal/processor)

The `internal/processor` package provides security analysis and report generation capabilities. It uses the canonical finding and severity types from the `internal/analysis` package.

### Finding and Severity Types

The processor package re-exports the canonical types from `internal/analysis`:

```go
// Finding is a type alias for the canonical analysis.Finding type
type Finding = analysis.Finding

// Severity is a type alias for the canonical analysis.Severity type
type Severity = analysis.Severity

// Severity constants re-exported from the canonical analysis package
const (
    SeverityCritical = analysis.SeverityCritical
    SeverityHigh     = analysis.SeverityHigh
    SeverityMedium   = analysis.SeverityMedium
    SeverityLow      = analysis.SeverityLow
    SeverityInfo     = analysis.SeverityInfo
)
```

See the [Analysis Package](#analysis-package-internalanalysis) section for the complete struct definition and field descriptions.

## Error Handling

All packages use standard Go error handling with context-aware error wrapping:

```go
if err := someOperation(); err != nil {
    return fmt.Errorf("operation context: %w", err)
}
```

### Sentinel Errors

```go
// cfgparser package
var ErrMissingOpnSenseDocumentRoot = errors.New("invalid XML: missing opnsense root element")

// converter package
var ErrNilDevice = errors.New("device configuration is nil")
```

## Extension Points

### Adding New Commands

1. Create command file in `cmd/`
2. Implement command with `CommandContext` pattern
3. Add to root command in `init()`
4. Update help text

### Adding Configuration Options

1. Add field to `Config` struct in `internal/config/config.go`
2. Set default in `LoadConfigWithViper`
3. Add CLI flag in appropriate command file
4. Add validation if needed
5. Update documentation

### Adding New Output Formats

1. Implement the `Generator` interface in `internal/converter/`
2. Register the format in the convert command
3. Add tests and documentation

---

This API reference covers the internal interfaces. For the most up-to-date information, refer to the source code and inline documentation.
