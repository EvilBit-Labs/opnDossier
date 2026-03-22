# Configuration Reference

Complete reference for all opnDossier configuration options. Configuration can be set via command-line flags, environment variables, or configuration file with clear precedence order.

For how configuration precedence works, see the [Configuration Guide](configuration.md).

## Global Options

These options apply to all commands (`audit`, `convert`, `display`, `validate`).

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
| Device type     | `--device-type` | -                        | -             | string  | `""`     | Force device type (auto-detected if empty) |
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

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                                                                                                     |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------- |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections: system, network, firewall, services, security                                                         |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols)                                                                       |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping (alias for --wrap 0)                                                                      |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive detailed reports                                                                         |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include all system tunables in report output (markdown, text, HTML only; JSON/YAML always include all tunables) |
| Redact           | `--redact`           | -                     | -           | boolean  | `false` | Redact sensitive fields (passwords, keys, etc.)                                                                 |

### Audit & Compliance (convert command only)

| Setting       | CLI Flag          | Environment Variable | Config File | Type     | Default | Description                                                                                                                                                              |
| ------------- | ----------------- | -------------------- | ----------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Audit mode    | `--audit-mode`    | -                    | -           | string   | `""`    | Audit mode: standard, blue, red (for backward compatibility; use `audit` command for dedicated audit workflows)                                                         |
| Audit plugins | `--audit-plugins` | -                    | -           | string[] | `[]`    | Plugins: stig, sans, firewall                                                                                                                                            |
| Plugin dir    | `--plugin-dir`    | -                    | -           | string   | `""`    | Directory containing dynamic .so compliance plugins. If explicitly set to a nonexistent directory, fails with an error. If not specified, no dynamic plugins are loaded. |

## Audit Command Options

The `audit` command is the dedicated entry point for security audit and compliance checks. See the [audit command documentation](commands/audit.md) for complete details.

### Audit-Specific Flags

| Setting          | CLI Flag     | Type     | Default      | Description                                                                                                 |
| ---------------- | ------------ | -------- | ------------ | ----------------------------------------------------------------------------------------------------------- |
| Audit mode       | `--mode`     | string   | `"standard"` | Audit mode: `standard` (neutral report), `blue` (defensive audit with compliance), `red` (attack surface)   |
| Compliance plugins | `--plugins`  | string[] | `[]`         | Comma-separated list: `stig`, `sans`, `firewall`. Only valid with `--mode blue`. Empty = all plugins run.  |
| Blackhat mode    | `--blackhat` | boolean  | `false`      | Enable blackhat commentary for red team reports (red mode only)                                             |
| Plugin directory | `--plugin-dir` | string | `""`         | Directory containing dynamic `.so` compliance plugins. Failed plugin loads are non-fatal (warnings logged). |

### Shared Output Flags

The `audit` command shares the following output and formatting flags with `convert`:

- `--format` / `-f` -- Output format (markdown, json, yaml, text, html)
- `--output` / `-o` -- Output file path (cannot be used with multiple input files)
- `--force` -- Overwrite existing files without prompt
- `--comprehensive` -- Generate detailed comprehensive reports
- `--redact` -- Redact sensitive fields (passwords, keys, etc.)
- `--wrap` -- Text wrap width
- `--no-wrap` -- Disable text wrapping
- `--include-tunables` -- Include all system tunables (markdown, text, HTML only)
- `--section` -- Filter output to specific sections

### Multi-File Audit Behavior

When auditing multiple files, the `--output` flag cannot be used. Each report is auto-named with an `-audit` suffix and format extension:

```bash
# Single file: --output allowed
opndossier audit config.xml --mode blue -o security-report.md

# Multiple files: auto-named outputs (config1-audit.md, config2-audit.md)
opndossier audit config1.xml config2.xml --mode blue
```

Path encoding for multi-file output:
- Bare filenames: `config.xml` → `config-audit.md`
- Paths with directories: `prod/site-a/config.xml` → `prod_site-a_config-audit.md`

### Usage Examples

```bash
# Blue team audit with all plugins (default when no --plugins specified)
opndossier audit config.xml --mode blue

# Blue team audit with specific plugins
opndossier audit config.xml --mode blue --plugins stig,sans

# Red team audit with blackhat commentary
opndossier audit config.xml --mode red --blackhat

# Custom plugins directory
opndossier audit config.xml --mode blue --plugin-dir /opt/plugins

# Multi-file audit with JSON output
opndossier audit config1.xml config2.xml --mode blue --format json
```

**Relationship to convert:** The `audit` command is the dedicated entry point for audit workflows. The `convert --audit-mode` flags remain available for backward compatibility but are not the primary interface.

## Display Command Options

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                                                                                                     |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------- |
| Theme            | `--theme`            | `OPNDOSSIER_THEME`    | `theme`     | string   | `""`    | Rendering theme: auto, dark, light, none                                                                        |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections: system, network, firewall, services, security                                                         |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols)                                                                       |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping                                                                                           |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive reports                                                                                  |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include all system tunables in report output (markdown, text, HTML only; JSON/YAML always include all tunables) |
| Redact           | `--redact`           | -                     | -           | boolean  | `false` | Redact sensitive fields in output                                                                               |

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
- [Audit Command](commands/audit.md) -- dedicated security audit and compliance checks
- [XML Field Reference](../xml-field-reference.md) -- OPNsense XML schema details
