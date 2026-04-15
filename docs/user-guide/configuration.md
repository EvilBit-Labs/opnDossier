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
# ~/.opnDossier.yaml

# Logging configuration
verbose: false
quiet: false

# Output settings
format: markdown
wrap: 120

# Content options
sections: []
```

### Configuration Options

| Option        | Type     | Default      | Description                                                                                         |
| ------------- | -------- | ------------ | --------------------------------------------------------------------------------------------------- |
| `verbose`     | boolean  | `false`      | Enable info-level logging (warnings, errors, and informational messages)                            |
| `debug`       | boolean  | `false`      | Enable debug mode - shows all messages for troubleshooting (mutually exclusive with verbose/quiet)  |
| `quiet`       | boolean  | `false`      | Suppress all output except errors                                                                   |
| `format`      | string   | `"markdown"` | Output format (markdown, json, yaml, text, html)                         |
| `theme`       | string   | `""`         | Display theme (auto, dark, light, none)                                  |
| `wrap`        | int      | `-1`         | Text wrap width (-1=auto, 0=off, >0=columns)                             |
| `sections`    | string[] | `[]`         | Sections to include in output                                            |
| `input_file`  | string   | `""`         | Default input file path                                                  |
| `output_file` | string   | `""`         | Default output file path                                                 |
| `no_progress` | boolean  | `false`      | Disable progress indicators                                              |
| `json_output` | boolean  | `false`      | Output validation errors in JSON format (validate command only)          |
| `minimal`     | boolean  | `false`      | Minimal output mode                                                      |

## Environment Variables

All configuration options can be set using environment variables with the `OPNDOSSIER_` prefix:

```bash
# Logging configuration
export OPNDOSSIER_VERBOSE=true
export OPNDOSSIER_DEBUG=false
export OPNDOSSIER_QUIET=false

# Output settings
export OPNDOSSIER_FORMAT=json
export OPNDOSSIER_WRAP=100

# File paths
export OPNDOSSIER_INPUT_FILE="/path/to/config.xml"
export OPNDOSSIER_OUTPUT_FILE="./documentation.md"
```

### Environment Variable Naming

Environment variables follow this pattern:

- Prefix: `OPNDOSSIER_`
- Key transformation: Convert config key to uppercase and replace `-` with `_`
- Examples:
  - `verbose` -> `OPNDOSSIER_VERBOSE`
  - `input_file` -> `OPNDOSSIER_INPUT_FILE`
  - `no_progress` -> `OPNDOSSIER_NO_PROGRESS`

## Command-Line Flags

Command-line flags have the highest precedence and override both environment variables and config file values. Global flags (like `--verbose` and `--quiet`) apply to all commands, while some flags are command-specific (like `--theme` for `display` or `--mode` for `audit`).

Each command's flags are documented on its own page under [Commands](commands/overview.md). For a single table listing every flag, environment variable, and config file key, see the [Configuration Reference](configuration-reference.md).

## Configuration Best Practices

### 1. Use Configuration Files for Persistent Settings

Store frequently used settings in `~/.opnDossier.yaml`:

```yaml
# Common settings for your environment
verbose: false
format: markdown
wrap: 120
```

### 2. Use Environment Variables for Deployment

For automated scripts and CI/CD pipelines:

```bash
#!/bin/bash
export OPNDOSSIER_QUIET=true
export OPNDOSSIER_FORMAT=json

opndossier convert config.xml -o report.json
```

### 3. Use CLI Flags for One-off Overrides

For temporary debugging or testing:

```bash
# Debug a specific run
opndossier --verbose convert problematic-config.xml

# Generate output to a different location
opndossier convert config.xml -o ./debug/output.md
```

## Troubleshooting Configuration

### Common Issues

1. **Configuration file not found**

   - Verify file exists at `~/.opnDossier.yaml`
   - Use `--config` flag to specify custom location

2. **Environment variables not working**

   - Ensure correct `OPNDOSSIER_` prefix
   - Use `true`/`false` for boolean values (not `1`/`0`)

3. **CLI flags not overriding config**

   - Verify flag syntax is correct
   - Check for typos in flag names

### Debug Configuration Loading

Use verbose mode to see configuration loading details:

```bash
opndossier --verbose --config /path/to/config.yaml convert config.xml
```

## Related

- [Configuration Reference](configuration-reference.md) -- complete lookup table of every flag, environment variable, and config file key
- [Commands Overview](commands/overview.md) -- per-command documentation with usage examples
