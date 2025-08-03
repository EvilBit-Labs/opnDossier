# API Reference

This document provides detailed information about the opnDossier API and its components.

## Migration Notice: New Validate Method

**Important for downstream consumers:** A new `Validate` method has been added to the `XMLParser` interface in this release.

### What Changed

The `XMLParser` now includes a dedicated validation method:

```go
// New method added to XMLParser interface
func (p *XMLParser) Validate(cfg *model.Opnsense) error
```

### Migration Guide

#### For Library Users

If you're using opnDossier as a library and have implemented custom parsers based on the `XMLParser` interface, you'll need to implement the new `Validate` method:

```go
// Before: Your custom parser only needed Parse method
type CustomParser struct{}

func (p *CustomParser) Parse(ctx context.Context, r io.Reader) (*model.Opnsense, error) {
    // Your implementation
}

// After: You must also implement Validate method
func (p *CustomParser) Validate(cfg *model.Opnsense) error {
    // Your validation implementation
    // You can return nil if no validation is needed
    return nil
}
```

#### For CLI Users

No changes are required for CLI usage. The validation is automatically integrated into existing commands.

#### Recommended Integration

For new integrations, consider using the combined `ParseAndValidate` method:

```go
// Recommended approach for new code
parser := parser.NewXMLParser()
cfg, err := parser.ParseAndValidate(ctx, reader)
if err != nil {
    // Handle both parse and validation errors
    return err
}
```

#### Backward Compatibility

Existing code using only the `Parse` method will continue to work without validation. Validation is opt-in through explicit method calls or CLI flags.

## Overview

opnDossier is structured with clear separation between CLI interface (cmd/) and internal implementation (internal/). This design ensures maintainable code while providing stable interfaces for future extensions.

## Package Structure

```text
opndossier/
├── cmd/                    # CLI commands (public interface)
├── internal/
│   ├── config/            # Configuration management
│   ├── parser/            # XML parsing
│   ├── converter/         # Data conversion
│   ├── display/           # Terminal output
│   ├── export/            # File operations
│   └── log/               # Logging utilities
└── main.go                # Application entry point
```

## CLI Package (cmd/)

### Root Command

The root command provides the main CLI interface with global configuration management.

#### Functions

##### `GetRootCmd() *cobra.Command`

Returns the root Cobra command for the opnDossier CLI application.

```go
rootCmd := cmd.GetRootCmd()
rootCmd.Execute()
```

##### `GetLogger() *log.Logger`

Returns the current application logger instance configured with user settings. This returns a `*log.Logger` from the internal/log package, which wraps `charmbracelet/log.Logger` for structured logging.

```go
logger := cmd.GetLogger()
logger.Info(\"Operation completed\", \"file\", filename)
```

##### `GetConfig() *config.Config`

Returns the current application configuration instance with all precedence applied.

```go
cfg := cmd.GetConfig()
if cfg.IsVerbose() {
    // Enable detailed logging
}
```

#### Global Flags

All commands inherit these global flags:

| Flag            | Type   | Default              | Description                          |
| --------------- | ------ | -------------------- | ------------------------------------ |
| `--config`      | string | `~/.opnDossier.yaml` | Configuration file path              |
| `--verbose, -v` | bool   | false                | Enable debug logging                 |
| `--quiet, -q`   | bool   | false                | Suppress non-error output            |
| `--log_level`   | string | "info"               | Log level (debug, info, warn, error) |
| `--log_format`  | string | "text"               | Log format (text, json)              |

### Convert Command

The convert command processes OPNsense configuration files.

#### Usage

```bash
opndossier convert [file ...] [flags]
```

#### Flags

| Flag           | Type   | Default | Description      |
| -------------- | ------ | ------- | ---------------- |
| `--output, -o` | string | ""      | Output file path |

#### Examples

```go
// Programmatic usage (if needed for testing)
convertCmd := cmd.GetRootCmd().Commands()[0] // \"convert\" command
convertCmd.SetArgs([]string{\"config.xml\", \"-o\", \"output.md\"})
err := convertCmd.Execute()
```

## Configuration Package (internal/config)

### Types

#### Config

```go
type Config struct {
    InputFile  string `mapstructure:\"input_file\"`
    OutputFile string `mapstructure:\"output_file\"`
    Verbose    bool   `mapstructure:\"verbose\"`
    Quiet      bool   `mapstructure:\"quiet\"`
    LogLevel   string `mapstructure:\"log_level\"`
    LogFormat  string `mapstructure:\"log_format\"`
}
```

#### ValidationError

```go
type ValidationError struct {
    Field   string
    Message string
}
```

### Functions

#### `LoadConfig(cfgFile string) (*Config, error)`

Loads configuration from file, environment variables, and defaults.

```go
cfg, err := config.LoadConfig(\"\") // Use default location
if err != nil {
    return fmt.Errorf(\"config load failed: %w\", err)
}
```

#### `LoadConfigWithFlags(cfgFile string, flags *pflag.FlagSet) (*Config, error)`

Loads configuration with CLI flag binding for proper precedence.

```go
cfg, err := config.LoadConfigWithFlags(configFile, cmd.Flags())
if err != nil {
    return fmt.Errorf(\"config load failed: %w\", err)
}
```

### Methods

#### `(*Config).Validate() error`

Validates configuration for consistency and correctness.

```go
if err := cfg.Validate(); err != nil {
    log.Fatalf(\"Invalid configuration: %v\", err)
}
```

#### `(*Config).GetLogLevel() string`

Returns the configured log level.

#### `(*Config).GetLogFormat() string`

Returns the configured log format.

#### `(*Config).IsVerbose() bool`

Returns true if verbose logging is enabled.

#### `(*Config).IsQuiet() bool`

Returns true if quiet mode is enabled.

## Parser Package (internal/parser)

### Interfaces

#### XMLParser

```go
type XMLParser interface {
    Parse(ctx context.Context, reader io.Reader) (*OPNsense, error)
}
```

### Types

#### OPNsense

```go
type OPNsense struct {
    XMLName xml.Name `xml:\"opnsense\"`
    // Configuration structure mirrors OPNsense XML format
    System   System   `xml:\"system\"`
    Firewall Firewall `xml:\"filter\"`
    // Additional fields as needed
}
```

### Functions

#### `NewXMLParser() XMLParser`

Creates a new XML parser instance.

```go
parser := parser.NewXMLParser()
opnsense, err := parser.Parse(ctx, reader)
```

## Converter Package (internal/converter)

### Interfaces

#### MarkdownConverter

```go
type MarkdownConverter interface {
    ToMarkdown(ctx context.Context, opnsense *parser.OPNsense) (string, error)
}
```

### Functions

#### `NewMarkdownConverter() MarkdownConverter`

Creates a new markdown converter instance.

```go
converter := converter.NewMarkdownConverter()
markdown, err := converter.ToMarkdown(ctx, opnsenseConfig)
```

## Export Package (internal/export)

### Interfaces

#### FileExporter

```go
type FileExporter interface {
    Export(ctx context.Context, content string, filepath string) error
}
```

### Functions

#### `NewFileExporter() FileExporter`

Creates a new file exporter instance.

```go
exporter := export.NewFileExporter()
err := exporter.Export(ctx, markdownContent, \"output.md\")
```

## Log Package (internal/log)

The log package provides a wrapper around `charmbracelet/log` for structured logging with additional application-specific functionality.

### Types

#### Logger

```go
type Logger struct {
    *log.Logger  // Embeds charmbracelet/log.Logger
}
```

The `Logger` type wraps `charmbracelet/log.Logger` to provide structured logging capabilities with key-value pairs and context support.

#### Config

```go
type Config struct {
    Level           string
    Format          string
    Output          io.Writer
    ReportCaller    bool
    ReportTimestamp bool
}
```

### Functions

#### `New(config Config) (*Logger, error)`

Creates a new logger instance with the specified configuration. Returns a `*log.Logger` from the internal/log package that wraps `charmbracelet/log.Logger`.

```go
logger, err := log.New(log.Config{
    Level:           \"info\",
    Format:          \"text\",
    Output:          os.Stderr,
    ReportCaller:    true,
    ReportTimestamp: true,
})
if err != nil {
    return fmt.Errorf(\"failed to create logger: %w\", err)
}
```

### Methods

#### `(*Logger).Info(msg string, keyvals ...interface{})`

Logs an info-level message with optional key-value pairs.

```go
logger.Info(\"Processing file\", \"filename\", path, \"size\", fileSize)
```

#### `(*Logger).Debug(msg string, keyvals ...interface{})`

Logs a debug-level message with optional key-value pairs.

#### `(*Logger).Warn(msg string, keyvals ...interface{})`

Logs a warning-level message with optional key-value pairs.

#### `(*Logger).Error(msg string, keyvals ...interface{})`

Logs an error-level message with optional key-value pairs.

#### `(*Logger).WithContext(ctx context.Context) *Logger`

Returns a logger that includes context information.

```go
ctxLogger := logger.WithContext(ctx)
ctxLogger.Info(\"Starting operation\")
```

#### `(*Logger).WithFields(keyvals ...interface{}) *Logger`

Returns a logger with additional fields pre-configured.

```go
fileLogger := logger.WithFields(\"operation\", \"convert\", \"file\", filename)
fileLogger.Info(\"Processing started\")
```

## Configuration Precedence

The configuration system follows this precedence order (highest to lowest):

1. **CLI Flags** - Immediate overrides via command-line
2. **Environment Variables** - `OPNDOSSIER_*` prefixed variables
3. **Configuration File** - YAML file at `~/.opnDossier.yaml` or custom path
4. **Default Values** - Built-in defaults

### Environment Variable Mapping

| Config Field  | Environment Variable     | Default |
| ------------- | ------------------------ | ------- |
| `input_file`  | `OPNDOSSIER_INPUT_FILE`  | ""      |
| `output_file` | `OPNDOSSIER_OUTPUT_FILE` | ""      |
| `verbose`     | `OPNDOSSIER_VERBOSE`     | false   |
| `quiet`       | `OPNDOSSIER_QUIET`       | false   |
| `log_level`   | `OPNDOSSIER_LOG_LEVEL`   | "info"  |
| `log_format`  | `OPNDOSSIER_LOG_FORMAT`  | "text"  |

## Error Handling

### Error Types

All packages use standard Go error handling with context-aware error wrapping:

```go
if err := someOperation(); err != nil {
    return fmt.Errorf(\"operation failed: %w\", err)
}
```

### Validation Errors

Configuration validation errors implement a specific type:

```go
type ValidationError struct {
    Field   string
    Message string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf(\"validation error for field '%s': %s\", e.Field, e.Message)
}
```

### Best Practices

1. **Always wrap errors with context**
2. **Use structured logging for debugging**
3. **Validate inputs early**
4. **Return errors, don't log and return**

## Testing Interfaces

### Test Helpers

For testing CLI commands:

```go
func TestConvertCommand(t *testing.T) {
    // Set up test command
    cmd := cmd.GetRootCmd()
    cmd.SetArgs([]string{\"convert\", \"testdata/config.xml\"})

    // Capture output
    var buf bytes.Buffer
    cmd.SetOutput(&buf)

    // Execute and verify
    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Contains(t, buf.String(), \"expected output\")
}
```

For testing configuration:

```go
func TestConfigPrecedence(t *testing.T) {
    // Set environment variable
    t.Setenv(\"OPNDOSSIER_LOG_LEVEL\", \"debug\")

    // Load config
    cfg, err := config.LoadConfig(\"\")
    require.NoError(t, err)

    // Verify precedence
    assert.Equal(t, \"debug\", cfg.LogLevel)
}
```

## Extension Points

### Adding New Commands

1. Create command file in `cmd/`
2. Implement command with proper configuration precedence
3. Add to root command in init()
4. Update help text with configuration info

### Adding Configuration Options

1. Add field to `Config` struct
2. Set default in `LoadConfigWithViper`
3. Add CLI flag in `cmd/root.go`
4. Add validation if needed
5. Update documentation

### Adding New Output Formats

1. Create new converter implementing the interface
2. Add format option to configuration
3. Update convert command to handle new format
4. Add tests and documentation

---

This API reference covers the current stable interfaces. For the most up-to-date information, refer to the source code and inline documentation.
