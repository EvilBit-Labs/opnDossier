# Configuration Reference

Complete reference for all opnDossier configuration options. Configuration can be set via command-line flags, environment variables, or configuration file with clear precedence order.

## Configuration Precedence

Configuration sources are applied in this order (highest to lowest priority):

1. **Command-line flags** - Direct CLI arguments
2. **Environment variables** - `OPNDOSSIER_*` prefixed variables
3. **Configuration file** - `~/.opnDossier.yaml`
4. **Default values** - Built-in defaults

## Complete Configuration Options

### Logging & Output

| Setting         | CLI Flag    | Environment Variable | Config File | Type    | Default | Description                                           |
| --------------- | ----------- | -------------------- | ----------- | ------- | ------- | ----------------------------------------------------- |
| Verbose logging | `--verbose` | `OPNDOSSIER_VERBOSE` | `verbose`   | boolean | `false` | Enable debug/verbose output with detailed information |
| Quiet mode      | `--quiet`   | `OPNDOSSIER_QUIET`   | `quiet`     | boolean | `false` | Suppress all non-error output                         |

### Input & Output Files

| Setting     | CLI Flag       | Environment Variable     | Config File   | Type   | Default | Description                         |
| ----------- | -------------- | ------------------------ | ------------- | ------ | ------- | ----------------------------------- |
| Input file  | (positional)   | `OPNDOSSIER_INPUT_FILE`  | `input_file`  | string | -       | Path to OPNsense config.xml file    |
| Output file | `-o, --output` | `OPNDOSSIER_OUTPUT_FILE` | `output_file` | string | stdout  | Output file path for generated docs |

### Format & Display

| Setting       | CLI Flag       | Environment Variable | Config File | Type   | Default    | Description                                  |
| ------------- | -------------- | -------------------- | ----------- | ------ | ---------- | -------------------------------------------- |
| Output format | `-f, --format` | `OPNDOSSIER_FORMAT`  | `format`    | string | `markdown` | Output format: markdown, json, yaml          |
| Wrap width    | `--wrap`       | `OPNDOSSIER_WRAP`    | `wrap`      | int    | `120`      | Text wrap width for display command (0=auto) |
| Theme         | `--theme`      | `OPNDOSSIER_THEME`   | `theme`     | string | `auto`     | Display theme: auto, dark, light, notty      |

### Processing Options

| Setting          | CLI Flag             | Environment Variable          | Config File        | Type    | Default  | Description                                  |
| ---------------- | -------------------- | ----------------------------- | ------------------ | ------- | -------- | -------------------------------------------- |
| Validate         | `--validate`         | `OPNDOSSIER_VALIDATE`         | `validate`         | boolean | `false`  | Enable configuration validation              |
| Validation mode  | `--validation-mode`  | `OPNDOSSIER_VALIDATION_MODE`  | `validation_mode`  | string  | `strict` | Validation mode: strict, lenient, permissive |
| Include tunables | `--include-tunables` | `OPNDOSSIER_INCLUDE_TUNABLES` | `include_tunables` | boolean | `false`  | Include system tunables in output            |
| Streaming mode   | `--streaming`        | `OPNDOSSIER_STREAMING`        | `streaming`        | boolean | `false`  | Enable streaming for large files             |

### Template Options (Deprecated)

| Setting            | CLI Flag              | Environment Variable           | Config File         | Type    | Default | Description                                |
| ------------------ | --------------------- | ------------------------------ | ------------------- | ------- | ------- | ------------------------------------------ |
| Use template       | `--use-template`      | `OPNDOSSIER_USE_TEMPLATE`      | `use_template`      | boolean | `false` | Use template-based generation (deprecated) |
| Template directory | `--template-dir`      | `OPNDOSSIER_TEMPLATE_DIR`      | `template_dir`      | string  | -       | Custom template directory path             |
| Template override  | `--template-override` | `OPNDOSSIER_TEMPLATE_OVERRIDE` | `template_override` | boolean | `false` | Force template mode                        |

### Advanced Options

| Setting       | CLI Flag          | Environment Variable       | Config File     | Type    | Default | Description                           |
| ------------- | ----------------- | -------------------------- | --------------- | ------- | ------- | ------------------------------------- |
| Max memory    | `--max-memory`    | `OPNDOSSIER_MAX_MEMORY`    | `max_memory`    | string  | `500M`  | Maximum memory usage (e.g., 100M, 1G) |
| Timeout       | `--timeout`       | `OPNDOSSIER_TIMEOUT`       | `timeout`       | int     | `120`   | Processing timeout in seconds         |
| Show warnings | `--show-warnings` | `OPNDOSSIER_SHOW_WARNINGS` | `show_warnings` | boolean | `true`  | Display validation warnings           |
| Color output  | `--color`         | `OPNDOSSIER_COLOR`         | `color`         | string  | `auto`  | Color output: auto, always, never     |

## Configuration File Format

### YAML Configuration File

Create `~/.opnDossier.yaml` with your preferred settings:

```yaml
# Logging Configuration
verbose: false # Enable verbose output
quiet: false # Suppress non-error output

# File Paths
input_file: /path/to/default/config.xml
output_file: ./output.md

# Format & Display
format: markdown # markdown, json, yaml
wrap: 120 # Text wrap width (0 for auto)
theme: auto # auto, dark, light, notty

# Processing Options
validate: true # Enable validation
validation_mode: strict # strict, lenient, permissive
include_tunables: false # Include system tunables
streaming: false # Enable streaming mode

# Advanced Options
max_memory: 500M # Maximum memory usage
timeout: 120 # Timeout in seconds
show_warnings: true # Show validation warnings
color: auto # auto, always, never
```

### JSON Configuration File (Alternative)

opnDossier also supports JSON format:

```json
{
  "verbose": false,
  "quiet": false,
  "input_file": "/path/to/default/config.xml",
  "output_file": "./output.md",
  "format": "markdown",
  "wrap": 120,
  "theme": "auto",
  "validate": true,
  "validation_mode": "strict",
  "include_tunables": false,
  "streaming": false,
  "max_memory": "500M",
  "timeout": 120,
  "show_warnings": true,
  "color": "auto"
}
```

## Environment Variables

All configuration options can be set via environment variables with the `OPNDOSSIER_` prefix:

```bash
# Logging
export OPNDOSSIER_VERBOSE=true
export OPNDOSSIER_QUIET=false

# File Paths
export OPNDOSSIER_INPUT_FILE="/path/to/config.xml"
export OPNDOSSIER_OUTPUT_FILE="./documentation.md"

# Format & Display
export OPNDOSSIER_FORMAT=markdown
export OPNDOSSIER_WRAP=100
export OPNDOSSIER_THEME=dark

# Processing Options
export OPNDOSSIER_VALIDATE=true
export OPNDOSSIER_VALIDATION_MODE=lenient
export OPNDOSSIER_INCLUDE_TUNABLES=true
export OPNDOSSIER_STREAMING=true

# Advanced Options
export OPNDOSSIER_MAX_MEMORY=1G
export OPNDOSSIER_TIMEOUT=300
export OPNDOSSIER_SHOW_WARNINGS=true
export OPNDOSSIER_COLOR=always
```

## Command-Line Flag Examples

### Basic Usage

```bash
# Simple conversion with defaults
opnDossier convert config.xml

# Specify output file
opnDossier convert config.xml -o output.md

# Change output format
opnDossier convert -f json config.xml -o output.json
```

### Logging Options

```bash
# Verbose logging
opnDossier --verbose convert config.xml

# Quiet mode (errors only)
opnDossier --quiet convert config.xml
```

### Display Options

```bash
# Display in terminal
opnDossier display config.xml

# Custom wrap width
opnDossier display --wrap 100 config.xml

# Auto-detect terminal width
opnDossier display --wrap 0 config.xml

# Force specific theme
opnDossier display --theme dark config.xml
```

### Validation Options

```bash
# Validate without processing
opnDossier validate config.xml

# Validate and convert
opnDossier convert --validate config.xml -o output.md

# Lenient validation mode
opnDossier convert --validation-mode=lenient config.xml

# Show all warnings
opnDossier convert --show-warnings config.xml
```

### Advanced Options

```bash
# Increase memory limit for large files
opnDossier --max-memory=1G convert large-config.xml

# Increase timeout
opnDossier --timeout=300 convert config.xml

# Enable streaming for very large files
opnDossier --streaming convert huge-config.xml

# Include system tunables
opnDossier convert --include-tunables config.xml -o full-report.md
```

## Configuration Validation

opnDossier validates configuration values on startup. Invalid values will result in clear error messages:

```bash
# Invalid format
$ opnDossier convert -f invalid config.xml
Error: invalid format 'invalid', must be one of: markdown, json, yaml

# Invalid wrap width
$ opnDossier display --wrap -10 config.xml
Error: wrap width must be non-negative

# Invalid memory limit
$ opnDossier --max-memory=invalid convert config.xml
Error: invalid memory limit format, use format like '100M', '1G'
```

## Configuration Best Practices

### Local Development

Use configuration file for consistent local settings:

```yaml
# ~/.opnDossier.yaml
verbose: true
wrap: 100
theme: dark
```

### CI/CD Environments

Use environment variables for flexibility:

```bash
export OPNDOSSIER_VALIDATE=true
export OPNDOSSIER_QUIET=true
```

### Production Scripts

Use explicit CLI flags for clarity:

```bash
#!/bin/bash
opnDossier convert \
  --validate \
  --timeout=300 \
  config.xml -o report.md
```

### Airgapped Environments

Minimal configuration for offline operation:

```yaml
# ~/.opnDossier.yaml
input_file: /mnt/configs/opnsense-config.xml
output_file: /mnt/reports/firewall-docs.md
validate: true
streaming: false
```

## Troubleshooting Configuration

### Configuration Not Loading

Check file location and permissions:

```bash
# Verify config file exists
ls -la ~/.opnDossier.yaml

# Check file permissions
chmod 644 ~/.opnDossier.yaml

# Validate YAML syntax
yamllint ~/.opnDossier.yaml
```

### Environment Variables Not Working

Verify environment variable names and values:

```bash
# List all opnDossier environment variables
env | grep OPNDOSSIER

# Verify boolean values (use true/false, not 1/0)
export OPNDOSSIER_VERBOSE=true  # Correct
export OPNDOSSIER_VERBOSE=1     # Incorrect
```

### CLI Flags Not Overriding

Remember precedence order - CLI flags should override everything:

```bash
# This should enable verbose output (CLI flag)
OPNDOSSIER_VERBOSE=false opnDossier --verbose convert config.xml

# Verify flag is being parsed
opnDossier convert --help
```

## Related Documentation

- [User Guide](./usage.md)
- [Configuration Guide](./configuration.md)
- [Examples](../examples.md)
- [Contributing Guide](https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md)
