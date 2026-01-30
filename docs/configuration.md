# Configuration Guide

This document provides comprehensive documentation for opnDossier configuration, covering all available options, environment variables, CLI flags, and configuration patterns.

## Table of Contents

- [Configuration Precedence](#configuration-precedence)
- [Configuration File](#configuration-file)
  - [File Location](#file-location)
  - [File Format](#file-format)
  - [Complete Configuration Reference](#complete-configuration-reference)
- [Environment Variables](#environment-variables)
  - [Naming Convention](#naming-convention)
  - [Complete Environment Variable Reference](#complete-environment-variable-reference)
- [CLI Flags](#cli-flags)
  - [Global Flags](#global-flags)
  - [Command-Specific Flags](#command-specific-flags)
- [Configuration Sections](#configuration-sections)
  - [Basic Settings](#basic-settings)
  - [Display Settings](#display-settings)
  - [Export Settings](#export-settings)
  - [Logging Settings](#logging-settings)
  - [Validation Settings](#validation-settings)
- [Common Configuration Patterns](#common-configuration-patterns)
- [Config Commands](#config-commands)
- [Troubleshooting](#troubleshooting)

---

## Configuration Precedence

opnDossier uses a layered configuration system. When a setting is specified in multiple places, higher-precedence sources override lower ones:

| Priority | Source                | Description                               |
| -------- | --------------------- | ----------------------------------------- |
| 1 (High) | Command-line flags    | Direct CLI arguments (e.g., `--verbose`)  |
| 2        | Environment variables | Variables with `OPNDOSSIER_` prefix       |
| 3        | Configuration file    | YAML file (default: `~/.opnDossier.yaml`) |
| 4 (Low)  | Built-in defaults     | Hardcoded sensible defaults               |

### Example: Precedence in Action

```yaml
# ~/.opnDossier.yaml
verbose: false
format: markdown
```

```bash
# Environment variable
export OPNDOSSIER_FORMAT=json

# CLI invocation - verbose flag overrides config file, format uses env var
opnDossier --verbose convert config.xml

# Result:
# - verbose: true (from CLI flag)
# - format: json (from env var, overrides file)
```

---

## Configuration File

### File Location

By default, opnDossier looks for configuration at `~/.opnDossier.yaml`. You can specify a custom location:

```bash
# Use custom config file
opnDossier --config /path/to/custom-config.yaml convert config.xml

# Use config in current directory
opnDossier --config ./.opnDossier.yaml convert config.xml
```

### File Format

The configuration file uses YAML format. Both flat and nested structures are supported for backward compatibility.

### Complete Configuration Reference

```yaml
# opnDossier Configuration File
# ================================
# Configuration precedence (highest to lowest):
#   1. Command-line flags
#   2. Environment variables (OPNDOSSIER_*)
#   3. Configuration file
#   4. Built-in defaults

# ------------------------------------------------------------------------------
# Basic Settings (Flat)
# ------------------------------------------------------------------------------

# Default input file path (typically not set - use CLI argument)
input_file: ''

# Default output file path (empty = stdout)
output_file: ''

# Enable verbose logging (debug level)
verbose: false

# Enable quiet mode (suppress all except errors)
quiet: false

# Output format: markdown, md, json, yaml, yml
format: markdown

# Default theme for terminal output: light, dark, auto, none, custom
theme: ''

# Template name for generation
template: ''

# Sections to include in output (empty = all sections)
sections: []

# Text wrap width (-1 = auto-detect, 0 = no wrap, >0 = specific width)
wrap: -1

# Report generation engine: programmatic, template
engine: programmatic

# Enable template mode explicitly
use_template: false

# Output errors in JSON format for automation
json_output: false

# Minimal output mode (suppress progress and verbose messages)
minimal: false

# Disable progress indicators
no_progress: false

# ------------------------------------------------------------------------------
# Display Settings (Nested)
# ------------------------------------------------------------------------------

display:
  # Terminal width for display (-1 = auto-detect)
  width: -1

  # Enable pager for long output
  pager: false

  # Enable syntax highlighting
  syntax_highlighting: true

# ------------------------------------------------------------------------------
# Export Settings (Nested)
# ------------------------------------------------------------------------------

export:
  # Default export format: markdown, md, json, yaml, yml
  format: markdown

  # Default export directory
  directory: ''

  # Default export template
  template: ''

  # Create backup before overwriting
  backup: false

# ------------------------------------------------------------------------------
# Logging Settings (Nested)
# ------------------------------------------------------------------------------

logging:
  # Log level: debug, info, warn, error
  level: info

  # Log format: text, json
  format: text

# ------------------------------------------------------------------------------
# Validation Settings (Nested)
# ------------------------------------------------------------------------------

validation:
  # Enable strict validation
  strict: false

  # Enable XML schema validation
  schema_validation: false
```

---

## Environment Variables

### Naming Convention

All environment variables use the `OPNDOSSIER_` prefix with the following transformations:

- **Flat keys**: Convert to uppercase and prefix with `OPNDOSSIER_`

  - `verbose` -> `OPNDOSSIER_VERBOSE`
  - `input_file` -> `OPNDOSSIER_INPUT_FILE`

- **Nested keys**: Convert dots to underscores

  - `display.width` -> `OPNDOSSIER_DISPLAY_WIDTH`
  - `logging.level` -> `OPNDOSSIER_LOGGING_LEVEL`

### Complete Environment Variable Reference

| Configuration Key              | Environment Variable                      | Type     | Default        |
| ------------------------------ | ----------------------------------------- | -------- | -------------- |
| `input_file`                   | `OPNDOSSIER_INPUT_FILE`                   | string   | ""             |
| `output_file`                  | `OPNDOSSIER_OUTPUT_FILE`                  | string   | ""             |
| `verbose`                      | `OPNDOSSIER_VERBOSE`                      | boolean  | false          |
| `quiet`                        | `OPNDOSSIER_QUIET`                        | boolean  | false          |
| `format`                       | `OPNDOSSIER_FORMAT`                       | string   | "markdown"     |
| `theme`                        | `OPNDOSSIER_THEME`                        | string   | ""             |
| `template`                     | `OPNDOSSIER_TEMPLATE`                     | string   | ""             |
| `sections`                     | `OPNDOSSIER_SECTIONS`                     | []string | []             |
| `wrap`                         | `OPNDOSSIER_WRAP`                         | int      | -1             |
| `engine`                       | `OPNDOSSIER_ENGINE`                       | string   | "programmatic" |
| `use_template`                 | `OPNDOSSIER_USE_TEMPLATE`                 | boolean  | false          |
| `json_output`                  | `OPNDOSSIER_JSON_OUTPUT`                  | boolean  | false          |
| `minimal`                      | `OPNDOSSIER_MINIMAL`                      | boolean  | false          |
| `no_progress`                  | `OPNDOSSIER_NO_PROGRESS`                  | boolean  | false          |
| `display.width`                | `OPNDOSSIER_DISPLAY_WIDTH`                | int      | -1             |
| `display.pager`                | `OPNDOSSIER_DISPLAY_PAGER`                | boolean  | false          |
| `display.syntax_highlighting`  | `OPNDOSSIER_DISPLAY_SYNTAX_HIGHLIGHTING`  | boolean  | true           |
| `export.format`                | `OPNDOSSIER_EXPORT_FORMAT`                | string   | "markdown"     |
| `export.directory`             | `OPNDOSSIER_EXPORT_DIRECTORY`             | string   | ""             |
| `export.template`              | `OPNDOSSIER_EXPORT_TEMPLATE`              | string   | ""             |
| `export.backup`                | `OPNDOSSIER_EXPORT_BACKUP`                | boolean  | false          |
| `logging.level`                | `OPNDOSSIER_LOGGING_LEVEL`                | string   | "info"         |
| `logging.format`               | `OPNDOSSIER_LOGGING_FORMAT`               | string   | "text"         |
| `validation.strict`            | `OPNDOSSIER_VALIDATION_STRICT`            | boolean  | false          |
| `validation.schema_validation` | `OPNDOSSIER_VALIDATION_SCHEMA_VALIDATION` | boolean  | false          |

### Boolean Values

Boolean environment variables accept various formats:

```bash
# All these are valid "true" values:
export OPNDOSSIER_VERBOSE=true
export OPNDOSSIER_VERBOSE=TRUE
export OPNDOSSIER_VERBOSE=True
export OPNDOSSIER_VERBOSE=1

# All these are valid "false" values:
export OPNDOSSIER_VERBOSE=false
export OPNDOSSIER_VERBOSE=FALSE
export OPNDOSSIER_VERBOSE=False
export OPNDOSSIER_VERBOSE=0
```

### List Values

List values (like `sections`) use comma-separated strings:

```bash
export OPNDOSSIER_SECTIONS="system,network,firewall,dhcp"
```

---

## CLI Flags

### Global Flags

These flags are available on all commands:

| Flag        | Short | Description                                           |
| ----------- | ----- | ----------------------------------------------------- |
| `--config`  |       | Configuration file path (default: ~/.opnDossier.yaml) |
| `--verbose` | `-v`  | Enable verbose/debug output                           |
| `--quiet`   | `-q`  | Suppress all output except errors                     |

### Command-Specific Flags

#### convert

```bash
opnDossier convert [flags] <config.xml>
```

| Flag         | Short | Description                                | Default        |
| ------------ | ----- | ------------------------------------------ | -------------- |
| `--output`   | `-o`  | Output file path (default: stdout)         | ""             |
| `--format`   | `-f`  | Output format (markdown, json, yaml)       | "markdown"     |
| `--engine`   |       | Generation engine (programmatic, template) | "programmatic" |
| `--sections` |       | Sections to include (comma-separated)      | all            |
| `--force`    |       | Overwrite existing output file             | false          |

#### display

```bash
opnDossier display [flags] <config.xml>
```

| Flag      | Short | Description                             | Default |
| --------- | ----- | --------------------------------------- | ------- |
| `--wrap`  | `-w`  | Text wrap width (-1=auto, 0=none)       | -1      |
| `--theme` | `-t`  | Display theme (light, dark, auto, none) | "auto"  |

#### validate

```bash
opnDossier validate [flags] <config.xml>
```

| Flag       | Short | Description              | Default |
| ---------- | ----- | ------------------------ | ------- |
| `--strict` |       | Enable strict validation | false   |

---

## Configuration Sections

### Basic Settings

| Setting        | Type     | Default        | Valid Values                    | Description                       |
| -------------- | -------- | -------------- | ------------------------------- | --------------------------------- |
| `input_file`   | string   | ""             | Any valid file path             | Default input file path           |
| `output_file`  | string   | ""             | Any valid file path             | Default output file path          |
| `verbose`      | boolean  | false          | true, false                     | Enable debug-level logging        |
| `quiet`        | boolean  | false          | true, false                     | Suppress non-error output         |
| `format`       | string   | "markdown"     | markdown, md, json, yaml, yml   | Output format                     |
| `theme`        | string   | ""             | light, dark, auto, none, custom | Terminal display theme            |
| `template`     | string   | ""             | Template name                   | Template for generation           |
| `sections`     | []string | []             | Section names                   | Sections to include (empty = all) |
| `wrap`         | int      | -1             | -1, 0, or positive integer      | Text wrap width                   |
| `engine`       | string   | "programmatic" | programmatic, template          | Generation engine                 |
| `use_template` | boolean  | false          | true, false                     | Explicitly enable template mode   |
| `json_output`  | boolean  | false          | true, false                     | Output errors as JSON             |
| `minimal`      | boolean  | false          | true, false                     | Minimal output mode               |
| `no_progress`  | boolean  | false          | true, false                     | Disable progress indicators       |

### Display Settings

Nested under `display:` in the configuration file.

| Setting               | Type    | Default | Valid Values           | Description                     |
| --------------------- | ------- | ------- | ---------------------- | ------------------------------- |
| `width`               | int     | -1      | -1, 0, or positive int | Terminal width (-1=auto-detect) |
| `pager`               | boolean | false   | true, false            | Enable pager for long output    |
| `syntax_highlighting` | boolean | true    | true, false            | Enable syntax highlighting      |

### Export Settings

Nested under `export:` in the configuration file.

| Setting     | Type    | Default    | Valid Values                  | Description                    |
| ----------- | ------- | ---------- | ----------------------------- | ------------------------------ |
| `format`    | string  | "markdown" | markdown, md, json, yaml, yml | Export format                  |
| `directory` | string  | ""         | Directory path                | Default export directory       |
| `template`  | string  | ""         | Template name                 | Export template                |
| `backup`    | boolean | false      | true, false                   | Create backup before overwrite |

### Logging Settings

Nested under `logging:` in the configuration file.

| Setting  | Type   | Default | Valid Values             | Description         |
| -------- | ------ | ------- | ------------------------ | ------------------- |
| `level`  | string | "info"  | debug, info, warn, error | Log verbosity level |
| `format` | string | "text"  | text, json               | Log output format   |

### Validation Settings

Nested under `validation:` in the configuration file.

| Setting             | Type    | Default | Valid Values | Description                  |
| ------------------- | ------- | ------- | ------------ | ---------------------------- |
| `strict`            | boolean | false   | true, false  | Enable strict validation     |
| `schema_validation` | boolean | false   | true, false  | Enable XML schema validation |

---

## Common Configuration Patterns

### Development/Debugging

```yaml
# ~/.opnDossier.yaml - Development configuration
verbose: true
logging:
  level: debug
  format: text
validation:
  strict: true
display:
  syntax_highlighting: true
  width: 120
```

### CI/CD Pipeline

```bash
#!/bin/bash
# CI/CD script with environment variables
export OPNDOSSIER_QUIET=true
export OPNDOSSIER_JSON_OUTPUT=true
export OPNDOSSIER_VALIDATION_STRICT=true
export OPNDOSSIER_NO_PROGRESS=true

opnDossier validate config.xml
opnDossier convert config.xml -o report.md
```

### Production/Automated Reports

```yaml
# ~/.opnDossier.yaml - Production configuration
verbose: false
quiet: false
minimal: true
no_progress: true
format: markdown
export:
  format: markdown
  backup: true
  directory: /var/reports/opnsense
logging:
  level: warn
  format: json
validation:
  strict: true
```

### Airgapped/Offline Environment

```yaml
# ~/.opnDossier.yaml - Airgapped system
input_file: /mnt/configs/opnsense-config.xml
output_file: /mnt/reports/firewall-documentation.md
verbose: false
quiet: false
engine: programmatic  # No external dependencies
export:
  backup: true
```

### JSON Output for Automation

```yaml
# ~/.opnDossier.yaml - Machine-parseable output
format: json
json_output: true
logging:
  format: json
quiet: true
no_progress: true
```

---

## Config Commands

opnDossier provides commands to manage configuration:

### config init

Generate a template configuration file:

```bash
# Create default config at ~/.opnDossier.yaml
opnDossier config init

# Create config at specific path
opnDossier config init --output /path/to/config.yaml

# Overwrite existing config
opnDossier config init --force
```

### config show

Display current effective configuration:

```bash
# Show all configuration values (styled terminal output)
opnDossier config show

# Show config in JSON format (for scripting)
opnDossier config show --json
```

### config validate

Validate configuration file:

```bash
# Validate default config file
opnDossier config validate

# Validate specific config file
opnDossier config validate --config /path/to/config.yaml
```

---

## Troubleshooting

### Configuration File Not Found

**Symptom:** opnDossier uses defaults instead of your configuration.

**Solution:**

```bash
# Verify config file exists
ls -la ~/.opnDossier.yaml

# Check file permissions (should be readable)
chmod 644 ~/.opnDossier.yaml

# Explicitly specify config path
opnDossier --config ~/.opnDossier.yaml convert config.xml
```

### Environment Variables Not Working

**Symptom:** Environment variables are ignored.

**Solutions:**

1. Check prefix is correct:

   ```bash
   # List all opnDossier environment variables
   env | grep OPNDOSSIER
   ```

2. Verify variable names match exactly:

   ```bash
   # Correct
   export OPNDOSSIER_VERBOSE=true

   # Wrong (missing underscore)
   export OPNDOSSIERVERBOSE=true
   ```

3. For nested config, use underscore separator:

   ```bash
   # Correct
   export OPNDOSSIER_DISPLAY_WIDTH=120

   # Wrong (dot separator)
   export OPNDOSSIER_DISPLAY.WIDTH=120
   ```

### Validation Errors

**Symptom:** Configuration fails validation with error messages.

**Solution:** Use `config validate` to see detailed error information:

```bash
opnDossier config validate --config /path/to/config.yaml
```

Common validation errors:

| Error                             | Solution                                       |
| --------------------------------- | ---------------------------------------------- |
| "invalid theme value"             | Use: light, dark, auto, none, or custom        |
| "invalid format"                  | Use: markdown, md, json, yaml, or yml          |
| "invalid log level"               | Use: debug, info, warn, or error               |
| "invalid engine"                  | Use: programmatic or template                  |
| "wrap width must be >= -1"        | Use -1 (auto), 0 (no wrap), or positive number |
| "input file does not exist"       | Check file path and permissions                |
| "output directory does not exist" | Create directory with `mkdir -p`               |

### CLI Flags Not Overriding Config

**Symptom:** CLI flags seem to be ignored.

**Solutions:**

1. Verify flag syntax is correct:

   ```bash
   # Correct
   opnDossier --verbose convert config.xml

   # Wrong (flag after command)
   opnDossier convert --verbose config.xml  # May work for some flags
   ```

2. Global flags must come before the command:

   ```bash
   # Correct
   opnDossier --config custom.yaml --verbose convert config.xml
   ```

3. Check for typos in flag names:

   ```bash
   # Show available flags
   opnDossier convert --help
   ```

### Debug Configuration Loading

Enable verbose mode to see configuration details:

```bash
opnDossier --verbose config show
```

This displays:

- Configuration file path being used
- Environment variables detected
- Final merged configuration values

---

## Related Documentation

- [Usage Guide](./user-guide/usage.md) - General usage instructions
- [API Reference](./api.md) - Programmatic API documentation
- [Examples](./examples.md) - Practical usage examples
