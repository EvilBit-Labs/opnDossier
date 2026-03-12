# Configuration Reference

Complete reference for all opnDossier configuration options. Configuration can be set via command-line flags, environment variables, or configuration file with clear precedence order.

For how configuration precedence works, see the [Configuration Guide](configuration.md).

## Global Options

These options apply to all commands (`convert`, `display`, `validate`).

### Logging & Output

| Setting         | CLI Flag        | Environment Variable     | Config File   | Type    | Default  | Description                                |
| --------------- | --------------- | ------------------------ | ------------- | ------- | -------- | ------------------------------------------ |
| Verbose logging | `--verbose`     | `OPNDOSSIER_VERBOSE`     | `verbose`     | boolean | `false`  | Enable debug-level logging                 |
| Quiet mode      | `--quiet`       | `OPNDOSSIER_QUIET`       | `quiet`       | boolean | `false`  | Suppress all output except errors          |
| Color output    | `--color`       | `OPNDOSSIER_COLOR`       | -             | string  | `"auto"` | Color output: auto, always, never          |
| No progress     | `--no-progress` | `OPNDOSSIER_NO_PROGRESS` | `no_progress` | boolean | `false`  | Disable progress indicators                |
| Timestamps      | `--timestamps`  | -                        | -             | boolean | `false`  | Include timestamps in log output           |
| Minimal mode    | `--minimal`     | `OPNDOSSIER_MINIMAL`     | `minimal`     | boolean | `false`  | Minimal output (suppress progress/verbose) |
| JSON output     | `--json-output` | `OPNDOSSIER_JSON_OUTPUT` | `json_output` | boolean | `false`  | Output errors in JSON format               |
| Device type     | `--device-type` | -                        | -             | string  | `""`     | Force device type (e.g., opnsense)         |
| Config file     | `--config`      | -                        | -             | string  | `""`     | Custom config file path                    |

## Convert Command Options

### Output Control

| Setting     | CLI Flag       | Environment Variable     | Config File   | Type    | Default      | Description                             |
| ----------- | -------------- | ------------------------ | ------------- | ------- | ------------ | --------------------------------------- |
| Output file | `-o, --output` | `OPNDOSSIER_OUTPUT_FILE` | `output_file` | string  | stdout       | Output file path                        |
| Format      | `-f, --format` | `OPNDOSSIER_FORMAT`      | `format`      | string  | `"markdown"` | Output format (see below)               |
| Force       | `--force`      | -                        | -             | boolean | `false`      | Overwrite existing files without prompt |

Supported formats: `markdown` (`md`), `json`, `yaml` (`yml`), `text` (`txt`), `html` (`htm`)

### Content & Formatting

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                                             |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | ------------------------------------------------------- |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections: system, network, firewall, services, security |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols)               |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping (alias for --wrap 0)              |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive detailed reports                 |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include system tunables in output                       |
| Redact           | `--redact`           | -                     | -           | boolean  | `false` | Redact sensitive fields (passwords, keys, etc.)         |

### Audit & Compliance

| Setting       | CLI Flag          | Environment Variable | Config File | Type     | Default | Description                     |
| ------------- | ----------------- | -------------------- | ----------- | -------- | ------- | ------------------------------- |
| Audit mode    | `--audit-mode`    | -                    | -           | string   | `""`    | Audit mode: standard, blue, red |
| Audit plugins | `--audit-plugins` | -                    | -           | string[] | `[]`    | Plugins: stig, sans, firewall   |

## Display Command Options

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                                             |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | ------------------------------------------------------- |
| Theme            | `--theme`            | `OPNDOSSIER_THEME`    | `theme`     | string   | `""`    | Rendering theme: auto, dark, light, none                |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections: system, network, firewall, services, security |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols)               |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping                                   |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive reports                          |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include system tunables in output                       |
| Redact           | `--redact`           | -                     | -           | boolean  | `false` | Redact sensitive fields in output                       |

## Validate Command Options

The validate command uses only global flags. It has no command-specific flags.

## Configuration File Format

### YAML Configuration File

Create `~/.opnDossier.yaml` with your preferred settings:

```yaml
# Logging Configuration
verbose: false
quiet: false

# Output Settings
format: markdown
wrap: 120
sections: []

# File Paths
input_file: ''
output_file: ''

# Display
theme: ''

# Advanced
no_progress: false
json_output: false
minimal: false
```

## Environment Variables

All configuration options can be set via environment variables with the `OPNDOSSIER_` prefix:

```bash
# Logging
export OPNDOSSIER_VERBOSE=true
export OPNDOSSIER_QUIET=false

# Output
export OPNDOSSIER_FORMAT=markdown
export OPNDOSSIER_WRAP=100

# File Paths
export OPNDOSSIER_INPUT_FILE="/path/to/config.xml"
export OPNDOSSIER_OUTPUT_FILE="./documentation.md"
```

## Configuration Validation

opnDossier validates configuration values on startup. Invalid values will result in clear error messages:

```bash
# Invalid format
$ opndossier convert -f invalid config.xml
Error: invalid format "invalid", must be one of: markdown, md, json, yaml, yml, text, txt, html, htm

# Mutually exclusive flags
$ opndossier --verbose --quiet convert config.xml
Error: if any flags in the group [verbose quiet] are set none of the others can be

# Invalid color mode
$ opndossier --color invalid convert config.xml
Error: invalid color "invalid", must be one of: auto, always, never
```

## Related

- [Configuration Guide](configuration.md) -- how to configure opnDossier
- [Commands Overview](commands/overview.md) -- per-command flag reference
- [XML Field Reference](../xml-field-reference.md) -- OPNsense XML schema details
