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
    Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, error)
    ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, error)
}
```

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
device, err := factory.CreateDevice(context.Background(), file, "", false)
if err != nil {
    return fmt.Errorf("parse failed: %w", err)
}

// With validation
device, err := factory.CreateDevice(context.Background(), file, "", true)
if err != nil {
    return fmt.Errorf("parse and validate failed: %w", err)
}
```

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

See [Plugin Development Guide](plugin-development.md) for details.

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
