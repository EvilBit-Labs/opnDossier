# Configuration Reference

Complete reference for all opnDossier configuration options. Configuration can be set via command-line flags, environment variables, or configuration file with clear precedence order.

## Configuration Precedence

Configuration sources are applied in this order (highest to lowest priority):

1. **Command-line flags** - Direct CLI arguments
2. **Environment variables** - `OPNDOSSIER_*` prefixed variables
3. **Configuration file** - `~/.opnDossier.yaml`
4. **Default values** - Built-in defaults

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

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                                |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | ------------------------------------------ |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections to include (comma-separated)      |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols)  |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping (alias for --wrap 0) |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive detailed reports    |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include system tunables in output          |

### Audit & Compliance

| Setting       | CLI Flag           | Environment Variable | Config File | Type     | Default | Description                           |
| ------------- | ------------------ | -------------------- | ----------- | -------- | ------- | ------------------------------------- |
| Audit mode    | `--audit-mode`     | -                    | -           | string   | `""`    | Audit mode: standard, blue, red       |
| Audit plugins | `--audit-plugins`  | -                    | -           | string[] | `[]`    | Plugins: stig, sans, firewall         |
| Blackhat mode | `--audit-blackhat` | -                    | -           | boolean  | `false` | Enable blackhat commentary (red mode) |

## Display Command Options

| Setting          | CLI Flag             | Environment Variable  | Config File | Type     | Default | Description                               |
| ---------------- | -------------------- | --------------------- | ----------- | -------- | ------- | ----------------------------------------- |
| Theme            | `--theme`            | `OPNDOSSIER_THEME`    | `theme`     | string   | `""`    | Rendering theme: auto, dark, light, none  |
| Sections         | `--section`          | `OPNDOSSIER_SECTIONS` | `sections`  | string[] | `[]`    | Sections to include (comma-separated)     |
| Wrap width       | `--wrap`             | `OPNDOSSIER_WRAP`     | `wrap`      | int      | `-1`    | Text wrap width (-1=auto, 0=off, >0=cols) |
| No wrap          | `--no-wrap`          | -                     | -           | boolean  | `false` | Disable text wrapping                     |
| Comprehensive    | `--comprehensive`    | -                     | -           | boolean  | `false` | Generate comprehensive reports            |
| Include tunables | `--include-tunables` | -                     | -           | boolean  | `false` | Include system tunables in output         |

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

## Command-Line Examples

### Basic Usage

```bash
# Simple conversion with defaults
opndossier convert config.xml

# Specify output file
opndossier convert config.xml -o output.md

# Change output format
opndossier convert -f json config.xml -o output.json
```

### Logging Options

```bash
# Verbose logging
opndossier --verbose convert config.xml

# Quiet mode (errors only)
opndossier --quiet convert config.xml
```

### Display Options

```bash
# Display in terminal
opndossier display config.xml

# Custom wrap width
opndossier display --wrap 100 config.xml

# Force specific theme
opndossier display --theme dark config.xml
```

### Validation

```bash
# Validate a configuration
opndossier validate config.xml

# Validate with JSON error output
opndossier --json-output validate config.xml
```

### Audit Mode

```bash
# Blue team audit with STIG and SANS
opndossier convert config.xml --audit-mode blue --audit-plugins stig,sans

# Red team recon with blackhat commentary
opndossier convert config.xml --audit-mode red --audit-blackhat

# Standard audit with all plugins
opndossier convert config.xml --audit-mode standard --audit-plugins stig,sans,firewall
```

## Configuration Validation

opnDossier validates configuration values on startup. Invalid values will result in clear error messages:

```bash
# Invalid format
$ opndossier convert -f invalid config.xml
Error: invalid format 'invalid', must be one of: markdown, md, json, yaml, yml, text, txt, html, htm

# Mutually exclusive flags
$ opndossier --verbose --quiet convert config.xml
Error: `verbose` and `quiet` are mutually exclusive

# Invalid color mode
$ opndossier --color invalid convert config.xml
Error: invalid color "invalid", must be one of: auto, always, never
```

## XML Schema Field Reference

This section documents the OPNsense config.xml fields that opnDossier parses and validates, with XML examples showing each field's usage.

### Source and Destination Fields

Firewall rule source and destination support multiple addressing modes. The fields `any`, `network`, and `address` are **mutually exclusive** -- only one should be present per source/destination block.

**Address-based rules (IP/CIDR or alias):**

```xml
<source>
  <address>192.168.1.0/24</address>
  <port>1024-65535</port>
</source>
```

**Network-based rules (interface subnet):**

```xml
<source>
  <network>lan</network>
</source>
```

**Negated rules (NOT semantics):**

```xml
<source>
  <not />
  <network>lan</network>
</source>
```

**Any address:**

```xml
<source>
  <any />
</source>
```

**Field priority:** Network > Address > Any (per OPNsense semantics)

### Advanced Rule Fields

**Floating rules (interface-independent):**

```xml
<rule>
  <floating>yes</floating>
  <direction>any</direction>
  <interface>wan,lan</interface>
  ...
</rule>
```

Floating rules require a `direction` field (`in`, `out`, or `any`).

**Policy routing:**

```xml
<rule>
  <gateway>WAN_GW</gateway>
  ...
</rule>
```

**State tracking:**

```xml
<rule>
  <statetype>keep state</statetype>
  <statetimeout>3600</statetimeout>
  ...
</rule>
```

Valid state types: `keep state`, `sloppy state`, `synproxy state`, `none`

### Rate-Limiting and DoS Protection

**Connection limits:**

```xml
<rule>
  <max-src-nodes>100</max-src-nodes>
  <max-src-conn>10</max-src-conn>
  <max-src-conn-rate>15/5</max-src-conn-rate>
  <max-src-conn-rates>300</max-src-conn-rates>
  ...
</rule>
```

The `max-src-conn-rate` field uses the format `connections/seconds` (e.g., `15/5` means 15 connections per 5 seconds).

**TCP flags matching:**

```xml
<rule>
  <tcpflags1>syn</tcpflags1>
  <tcpflags2>syn,ack</tcpflags2>
  ...
</rule>
```

**ICMP type filtering:**

```xml
<rule>
  <protocol>icmp</protocol>
  <icmptype>3,11,0</icmptype>
  ...
</rule>
```

### NAT Rule Enhancements

**Outbound NAT with port preservation:**

```xml
<rule>
  <staticnatport />
  <natport>1024-65535</natport>
  <poolopts_sourcehashkey>0x12345678</poolopts_sourcehashkey>
  ...
</rule>
```

**NAT exclusion:**

```xml
<rule>
  <nonat />
  ...
</rule>
```

**Inbound NAT with reflection:**

```xml
<rule>
  <natreflection>enable</natreflection>
  <associated-rule-id>5f1234567890abcd</associated-rule-id>
  <local-port>8080</local-port>
  ...
</rule>
```

Valid NAT reflection modes: `enable`, `disable`, `purenat`

## Related Documentation

- [Usage Guide](./usage.md)
- [Configuration Guide](./configuration.md)
- [Contributing Guide](https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md)
