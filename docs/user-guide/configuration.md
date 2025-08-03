# Configuration Guide

opnDossier provides flexible configuration management using **Viper** for layered configuration handling. This guide covers all configuration options and methods.

## Configuration Precedence

Configuration follows a clear precedence order:

1. **Command-line flags** (highest priority)
2. **Environment variables** (`OPNDOSSIER_*`)
3. **Configuration file** (`~/.opnDossier.yaml`)
4. **Default values** (lowest priority)

This precedence ensures that CLI flags always override environment variables and config files, making it easy to temporarily override settings for specific runs.

## Configuration File

### Location

The default configuration file location is `~/.opnDossier.yaml`. You can specify a custom location using the `--config` flag:

```bash
opndossier --config /path/to/custom/config.yaml convert config.xml
```

### Format

The configuration file uses YAML format:

```yaml
# ~/.opnDossier.yaml - opnDossier Configuration

# Input/Output settings
input_file: /path/to/default/config.xml
output_file: ./output.md

# Logging configuration
log_level: info       # debug, info, warn, error
log_format: text      # text, json
verbose: false        # Enable debug logging
quiet: false          # Suppress all output except errors
```

### Configuration Options

| Option        | Type    | Default | Description                         |
| ------------- | ------- | ------- | ----------------------------------- |
| `input_file`  | string  | ""      | Default input file path             |
| `output_file` | string  | ""      | Default output file path            |
| `verbose`     | boolean | false   | Enable verbose/debug logging        |
| `quiet`       | boolean | false   | Suppress all output except errors   |
| `log_level`   | string  | "info"  | Log level: debug, info, warn, error |
| `log_format`  | string  | "text"  | Log format: text, json              |

## Environment Variables

All configuration options can be set using environment variables with the `OPNDOSSIER_` prefix:

### Available Environment Variables

```bash
# Logging configuration
export OPNDOSSIER_VERBOSE=true          # Enable verbose/debug logging
export OPNDOSSIER_QUIET=false           # Suppress non-error output
export OPNDOSSIER_LOG_LEVEL=debug       # Set log level (debug, info, warn, error)
export OPNDOSSIER_LOG_FORMAT=json       # Use JSON log format

# File paths
export OPNDOSSIER_INPUT_FILE="/path/to/config.xml"
export OPNDOSSIER_OUTPUT_FILE="./documentation.md"
```

### Examples

```bash
# Set environment variables for a single run
OPNDOSSIER_VERBOSE=true OPNDOSSIER_LOG_FORMAT=json opndossier convert config.xml

# Export for multiple uses in the same session
export OPNDOSSIER_LOG_LEVEL=debug
export OPNDOSSIER_OUTPUT_FILE="./network-docs.md"
opndossier convert config.xml
```

### Environment Variable Naming

Environment variables follow this pattern:

- Prefix: `OPNDOSSIER_`
- Key transformation: Convert config key to uppercase and replace `-` with `_`
- Examples:
  - `log_level` → `OPNDOSSIER_LOG_LEVEL`
  - `input_file` → `OPNDOSSIER_INPUT_FILE`

## Command-Line Flags

CLI flags have the highest precedence and override all other configuration sources:

### Global Flags

```bash
# Configuration file
--config string       # Custom config file path (default: ~/.opnDossier.yaml)

# Logging options
--verbose, -v         # Enable verbose output (debug logging)
--quiet, -q           # Suppress all output except errors
--log_level string    # Set log level (debug, info, warn, error)
--log_format string   # Set log format (text, json)
```

### Convert Command Flags

The `convert` command has additional flags specific to file conversion:

```bash
--output, -o string   # Output file path for conversion results
```

### Usage Examples

```bash
# Override log level for debugging
opndossier --log_level=debug convert config.xml

# Use JSON logging with quiet mode
opndossier --quiet --log_format=json convert config.xml

# Verbose mode with custom output
opndossier --verbose convert config.xml --output detailed-output.md

# Use custom config file
opndossier --config ./project-config.yaml convert config.xml
```

## Logging Configuration

### Log Levels

| Level   | Description                            | Use Case                     |
| ------- | -------------------------------------- | ---------------------------- |
| `debug` | Detailed diagnostic information        | Development, troubleshooting |
| `info`  | General operational messages (default) | Normal operation             |
| `warn`  | Warning messages for potential issues  | Monitoring                   |
| `error` | Error messages for failures            | Error tracking               |

### Log Formats

#### Text Format (Default)

Human-readable format suitable for terminal output:

```text
2024-01-15 10:30:45 INFO Starting conversion process input_file=config.xml
2024-01-15 10:30:45 DEBUG Parsing XML file
2024-01-15 10:30:46 INFO Conversion completed successfully
```

#### JSON Format

Structured format suitable for log aggregation systems:

```json
[
  {
    "time": "2024-01-15T10:30:45Z",
    "level": "INFO",
    "msg": "Starting conversion process",
    "input_file": "config.xml"
  },
  {
    "time": "2024-01-15T10:30:45Z",
    "level": "DEBUG",
    "msg": "Parsing XML file"
  },
  {
    "time": "2024-01-15T10:30:46Z",
    "level": "INFO",
    "msg": "Conversion completed successfully"
  }
]
```

### Logging Examples

```bash
# Debug logging with text format
opndossier --log_level=debug convert config.xml

# JSON logging for log aggregation
opndossier --log_format=json convert config.xml

# Quiet mode - only errors
opndossier --quiet convert config.xml

# Verbose mode (shorthand for debug level)
opndossier --verbose convert config.xml
```

## Configuration Validation

opnDossier validates configuration settings and provides clear error messages for invalid configurations:

### Validation Rules

- `verbose` and `quiet` are mutually exclusive
- `log_level` must be one of: debug, info, warn, error
- `log_format` must be one of: text, json
- `input_file` must exist if specified
- `output_file` directory must exist if specified

### Validation Examples

```bash
# This will fail - mutually exclusive options
opndossier --verbose --quiet convert config.xml
# Error: verbose and quiet options are mutually exclusive

# This will fail - invalid log level
opndossier --log_level=trace convert config.xml
# Error: invalid log level 'trace', must be one of: debug, info, warn, error
```

## Configuration Best Practices

### 1. Use Configuration Files for Persistent Settings

Store frequently used settings in `~/.opnDossier.yaml`:

```yaml
# Common settings for your environment
log_level: info
log_format: text
output_file: ./network-documentation.md
```

### 2. Use Environment Variables for Deployment

For automated scripts and CI/CD pipelines:

```bash
#!/bin/bash
export OPNDOSSIER_LOG_FORMAT=json
export OPNDOSSIER_LOG_LEVEL=info
export OPNDOSSIER_OUTPUT_FILE="./build/network-docs.md"

opndossier convert config.xml
```

### 3. Use CLI Flags for One-off Overrides

For temporary debugging or testing:

```bash
# Debug a specific run
opndossier --verbose convert problematic-config.xml

# Generate output to a different location
opndossier convert config.xml --output ./debug/output.md
```

### 4. Airgapped Environment Configuration

For secure, offline environments:

```yaml
# ~/.opnDossier.yaml for airgapped systems
log_level: warn          # Minimal logging
log_format: text         # Human-readable
verbose: false
quiet: false
```

## Troubleshooting Configuration

### Common Issues

1. **Configuration file not found**

   - Verify file exists at `~/.opnDossier.yaml`
   - Use `--config` flag to specify custom location

2. **Environment variables not working**

   - Ensure correct `OPNDOSSIER_` prefix
   - Check variable names match expected format

3. **CLI flags not overriding config**

   - Verify flag syntax is correct
   - Check for typos in flag names

### Debug Configuration Loading

Use verbose mode to see configuration loading details:

```bash
opndossier --verbose --config /path/to/config.yaml convert config.xml
```

This will show:

- Which configuration file is loaded
- Which environment variables are detected
- Final configuration values after precedence resolution

---

For more configuration examples and advanced usage, see the [Usage Guide](usage.md).
