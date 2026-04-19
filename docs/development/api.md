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
├── internal/                    # Private application logic
│   ├── analysis/                # Canonical finding and severity types
│   ├── cfgparser/               # XML parsing and validation
│   ├── config/                  # Configuration management (Viper)
│   ├── converter/               # Data conversion and report generation
│   │   ├── builder/             # Programmatic markdown builder
│   │   └── formatters/          # Security scoring, transformers
│   ├── compliance/              # Plugin interfaces
│   ├── plugins/                 # Plugin implementations (stig, sans, firewall)
│   ├── audit/                   # Audit engine and plugin management
│   ├── display/                 # Terminal display formatting
│   ├── export/                  # File export functionality
│   ├── logging/                 # Structured logging (charmbracelet/log)
│   ├── progress/                # CLI progress indicators
│   ├── processor/               # Security analysis and report generation
│   └── validator/               # Configuration validation
├── pkg/                         # Public API packages
│   ├── model/                   # Platform-agnostic CommonDevice domain model
│   ├── parser/                  # Factory + DeviceParser interface
│   │   ├── opnsense/            # OPNsense parser + schema→CommonDevice converter
│   │   └── pfsense/             # pfSense parser + schema→CommonDevice converter
│   └── schema/
│       ├── opnsense/            # Canonical OPNsense XML data model structs
│       └── pfsense/             # Canonical pfSense XML data model structs
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

> [!NOTE]
> `--json-output` is a validate-command-only flag (not global). It outputs validation errors in JSON format for machine consumption.

## Parser Package (internal/cfgparser)

### DeviceParser Interface

The `DeviceParser` interface (defined in `pkg/parser/factory.go`) abstracts device-specific parsing behind a common contract:

```go
type DeviceParser interface {
    // Parse reads and converts the configuration, returning non-fatal conversion warnings.
    Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error)
    // ParseAndValidate reads, converts, and validates the configuration, returning non-fatal conversion warnings.
    ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error)
}
```

**Breaking Change:** Both methods return a 3-value tuple `(*CommonDevice, []ConversionWarning, error)` instead of the previous 2-value return `(*CommonDevice, error)`. Implementations must return non-fatal conversion warnings alongside the parsed device model. Callers should log or surface these warnings without treating them as errors.

The `parser.Factory` auto-detects device type from the XML root element and delegates to the appropriate `DeviceParser` via the registry. The underlying OPNsense XML parser (`internal/cfgparser/XMLParser`) still produces `schema.OpnSenseDocument`, which is then converted to `common.CommonDevice` by the OPNsense-specific parser in `pkg/parser/opnsense/`.

### DeviceParser Registry

The `DeviceParserRegistry` enables compile-time registration of device-specific parsers following the `database/sql` driver pattern. Parser packages self-register via `init()` functions, and consumers activate them through blank imports.

#### Registry Structure and Methods

```go
type DeviceParserRegistry struct {
    // Thread-safe registry of parser constructors keyed by device type
}

// ConstructorFunc is the factory function signature for creating DeviceParser instances.
type ConstructorFunc = func(OPNsenseXMLDecoder) DeviceParser

// Register adds a constructor for the given device type. Device type names are
// normalized to lowercase with whitespace trimmed. Panics on duplicate registration,
// nil factory, or empty device type to surface wiring conflicts at startup.
func (r *DeviceParserRegistry) Register(deviceType string, fn ConstructorFunc)

// Get returns the constructor for the given device type, or (nil, false) if not registered.
func (r *DeviceParserRegistry) Get(deviceType string) (ConstructorFunc, bool)

// List returns a sorted slice of all registered device type names.
func (r *DeviceParserRegistry) List() []string

// DefaultRegistry returns the package-level singleton registry.
func DefaultRegistry() *DeviceParserRegistry

// Register is a package-level convenience wrapper around DefaultRegistry().Register().
func Register(deviceType string, fn ConstructorFunc)
```

#### Self-Registration Pattern

Parser packages register themselves via `init()` functions:

```go
// In pkg/parser/opnsense/parser.go
func NewParserFactory(decoder parser.OPNsenseXMLDecoder) parser.DeviceParser {
    return NewParser(decoder)
}

func init() {
    parser.Register("opnsense", NewParserFactory)
}
```

#### Blank Import Requirement

**CRITICAL:** Code using `parser.NewFactory()` MUST include blank imports for all required parser packages:

```go
import (
    "github.com/EvilBit-Labs/opnDossier/pkg/parser"
    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // self-registers via init()
)
```

Missing the blank import causes "unsupported device type" errors and a supported device list that only includes a hint about missing blank imports. The parser implementation exists but its `init()` function never runs, so the registry remains empty. See [GOTCHAS.md section 7.1](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#71-blank-import-requirement) for details.

#### Test Isolation

For tests that need isolated registry state without polluting the global singleton:

```go
// Create a factory with a custom registry
registry := parser.NewDeviceParserRegistry()
registry.Register("testdevice", testConstructor)
factory := parser.NewFactoryWithRegistry(decoder, registry)
```

### Factory Usage

```go
import (
    "github.com/EvilBit-Labs/opnDossier/pkg/parser"
    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // Required: self-registers via init()
)

factory := parser.NewFactory(cfgparser.NewXMLParser())

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

// With validation — rewind the reader first; the previous CreateDevice consumed it.
if _, err := file.Seek(0, io.SeekStart); err != nil {
    return fmt.Errorf("rewind config.xml: %w", err)
}
device, warnings, err = factory.CreateDevice(context.Background(), file, "", true)
if err != nil {
    return fmt.Errorf("parse and validate failed: %w", err)
}
```

**Breaking Change:** `CreateDevice` returns a 3-value tuple `(*CommonDevice, []ConversionWarning, error)` instead of the previous 2-value return `(*CommonDevice, error)`. Warnings represent non-fatal conversion issues that should be logged but do not prevent successful parsing.

The underlying `XMLParser` (`internal/cfgparser/`) supports UTF-8, US-ASCII, ISO-8859-1 (Latin1), and Windows-1252 encodings. Input is limited to 10MB by default (`DefaultMaxInputSize`).

**Breaking Change:** `ParserFactory` / `NewParserFactory()` were renamed to `Factory` / `NewFactory()` to comply with Go naming conventions (`revive` stutters rule). The `internal/model/` re-export layer was removed; import `pkg/parser` directly. `NewFactory()` now requires an `OPNsenseXMLDecoder` argument (renamed from `XMLDecoder` in v1.5 to reflect that it returns `*schema.OpnSenseDocument`).

| Old                         | New                                           |
| --------------------------- | --------------------------------------------- |
| `parser.ParserFactory`      | `parser.Factory`                              |
| `parser.NewParserFactory()` | `parser.NewFactory(cfgparser.NewXMLParser())` |
| `model.NewParserFactory()`  | `parser.NewFactory(cfgparser.NewXMLParser())` |
| `parser.NewFactory()`       | `parser.NewFactory(cfgparser.NewXMLParser())` |

## Data Model (pkg/schema/opnsense, pkg/model)

### CommonDevice

The platform-agnostic device model, defined in `pkg/model/`:

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

The XML DTO remains as `schema.OpnSenseDocument` in `pkg/schema/opnsense/`. The OPNsense-specific parser in `pkg/parser/opnsense/` converts the XML DTO into `CommonDevice`. The `pkg/parser/` package provides the `Factory` and `DeviceParser` interface for consumers.

### Type Safety with Enums

The `pkg/model` package uses typed string enums to enforce compile-time validation of configuration values and eliminate typos in string literals. This provides better IDE autocomplete, refactoring support, and catches errors at build time instead of runtime.

#### Firewall Rule Types

Firewall rule actions use the `FirewallRuleType` enum instead of bare strings:

```go
type FirewallRuleType string

const (
    RuleTypePass   FirewallRuleType = "pass"    // Allow matching traffic
    RuleTypeBlock  FirewallRuleType = "block"   // Silently drop matching traffic
    RuleTypeReject FirewallRuleType = "reject"  // Drop and send rejection response
)
```

**Usage:**

```go
// Creating rules with typed constants
rule := common.FirewallRule{
    Type:        common.RuleTypePass,
    Description: "Allow HTTPS",
    // ...
}

// Comparing rule types
if rule.Type == common.RuleTypeBlock {
    // Handle blocked traffic
}

// Filtering rules by type
passRules := builder.FilterRulesByType(rules, common.RuleTypePass)
```

#### NAT Configuration

NAT outbound modes use the `NATOutboundMode` enum:

```go
type NATOutboundMode string

const (
    OutboundAutomatic NATOutboundMode = "automatic"  // Automatic outbound NAT rules
    OutboundHybrid    NATOutboundMode = "hybrid"     // Combined automatic and manual rules
    OutboundAdvanced  NATOutboundMode = "advanced"   // Manual rules only
    OutboundDisabled  NATOutboundMode = "disabled"   // Outbound NAT disabled
)
```

**Usage:**

```go
nat := common.NATConfig{
    OutboundMode: common.OutboundHybrid,
    // ...
}
```

#### IP Protocol and Direction

Additional typed enums for network configuration:

```go
type IPProtocol string

const (
    IPProtocolInet  IPProtocol = "inet"   // IPv4
    IPProtocolInet6 IPProtocol = "inet6"  // IPv6
)

type FirewallDirection string

const (
    DirectionIn  FirewallDirection = "in"   // Inbound traffic
    DirectionOut FirewallDirection = "out"  // Outbound traffic
    DirectionAny FirewallDirection = "any"  // Either direction
)
```

#### Network Configuration Types

Network features use typed enums for link aggregation and virtual IPs:

```go
type LAGGProtocol string

const (
    LAGGProtocolLACP        LAGGProtocol = "lacp"        // IEEE 802.3ad LACP
    LAGGProtocolFailover    LAGGProtocol = "failover"    // Active/standby failover
    LAGGProtocolLoadBalance LAGGProtocol = "loadbalance" // Hash-based distribution
    LAGGProtocolRoundRobin  LAGGProtocol = "roundrobin"  // Round-robin distribution
)

type VIPMode string

const (
    VIPModeCarp     VIPMode = "carp"     // CARP HA failover
    VIPModeIPAlias  VIPMode = "ipalias"  // Additional IP address
    VIPModeProxyARP VIPMode = "proxyarp" // ARP proxying
)
```

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
    // NOTE: ConversionWarning.Severity is `pkg/model.Severity` (string alias)
    // — NOT `analysis.Severity`. Use the `common.Severity*` constants exported
    // from `pkg/model` when constructing warnings.
    Severity common.Severity
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

// Filter rules by type using typed constants
passRules := builder.FilterRulesByType(rules, common.RuleTypePass)
blockRules := builder.FilterRulesByType(rules, common.RuleTypeBlock)
rejectRules := builder.FilterRulesByType(rules, common.RuleTypeReject)
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

#### RunComplianceChecks

The `RunComplianceChecks` method executes compliance checks for specified plugins:

```go
func (pr *PluginRegistry) RunComplianceChecks(
    device *common.CommonDevice,
    pluginNames []string,
    logger *logging.Logger,
) (*ComplianceResult, error)
```

**Parameters:**

- `device` (\*common.CommonDevice): The device configuration to audit (required; nil returns `ErrConfigurationNil`)
- `pluginNames` ([]string): List of plugin names to execute. Only the specified plugins run; an empty or nil slice results in zero plugins executed and an empty result
- `logger` (\*logging.Logger): Logger for panic recovery events (optional; nil creates a fallback logger internally)

**Panic Recovery:**

Each plugin's `RunChecks()` call is wrapped in a `defer recover()` boundary to prevent misbehaving plugins (especially dynamically-loaded ones) from crashing the entire audit process. When a plugin panics:

- The panic is caught and logged via the `*logging.Logger` with the plugin name, panic type, and stack trace
- The recovery path populates safe defaults (`PluginFindings`, `PluginInfo` with `Version: "unknown (panicked)"`, empty `Compliance` map) and skips further method calls on the potentially corrupt plugin
- The plugin appears in all result maps, ensuring downstream consumers can see it was requested
- Other plugins continue execution normally

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
    InfoFindings     int                            `json:"infoFindings"`
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
- `InfoFindings` (int): Count of info severity findings
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

### Adding Custom Device Parsers

External Go projects can register custom device parsers by:

1. **Implement the `DeviceParser` interface** in `pkg/parser/`:

   ```go
   type CustomParser struct {
       decoder parser.OPNsenseXMLDecoder
   }

   func (p *CustomParser) Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
       // Implementation
   }

   func (p *CustomParser) ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
       // Implementation with validation
   }
   ```

2. **Export a factory function** matching the `ConstructorFunc` signature:

   ```go
   func NewCustomParserFactory(decoder parser.OPNsenseXMLDecoder) parser.DeviceParser {
       return &CustomParser{decoder: decoder}
   }
   ```

3. **Register via `init()`** in your parser package:

   ```go
   func init() {
       parser.Register("customdevice", NewCustomParserFactory)
   }
   ```

4. **Add blank import** in the consuming application:

   ```go
   import (
       _ "your.module/pkg/parser/customdevice" // self-registers via init()
   )
   ```

See [docs/solutions/architecture-issues/pluggable-deviceparser-registry-pattern.md](../solutions/architecture-issues/pluggable-deviceparser-registry-pattern.md) for complete implementation details and examples.

---

This API reference covers the internal interfaces. For the most up-to-date information, refer to the source code and inline documentation.
