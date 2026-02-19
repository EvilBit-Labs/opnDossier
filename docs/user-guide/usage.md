# Usage Guide

This guide covers common workflows and examples for using opnDossier effectively.

## Commands Overview

opnDossier provides three core commands:

| Command    | Purpose                                                  |
| ---------- | -------------------------------------------------------- |
| `convert`  | Convert config.xml to structured output formats          |
| `display`  | Render config.xml as formatted markdown in terminal      |
| `validate` | Check config.xml for structural and semantic correctness |

## Convert Command

The primary command for transforming OPNsense configurations into documentation.

### Basic Conversion

```bash
# Convert to markdown (default format, prints to stdout)
opndossier convert config.xml

# Save to a file
opndossier convert config.xml -o documentation.md

# Force overwrite existing file without prompt
opndossier convert config.xml -o output.md --force
```

### Output Formats

opnDossier supports five output formats:

```bash
# Markdown (default)
opndossier convert config.xml -f markdown

# JSON
opndossier convert config.xml -f json -o output.json

# YAML
opndossier convert config.xml -f yaml -o output.yaml

# Plain text (markdown without formatting)
opndossier convert config.xml -f text -o output.txt

# Self-contained HTML report
opndossier convert config.xml -f html -o report.html
```

Short aliases are also supported: `md`, `yml`, `txt`, `htm`.

### Multiple Files

```bash
# Convert multiple files (each gets an auto-named output file)
opndossier convert config1.xml config2.xml config3.xml

# Convert multiple files to JSON
opndossier convert -f json config1.xml config2.xml
```

When processing multiple files, the `--output` flag is ignored and each output file is named based on its input file with the appropriate extension.

### Section Filtering

```bash
# Include only specific sections
opndossier convert config.xml --section system,network

# Available sections: system, network, firewall, services, security
```

### Text Wrapping

```bash
# Set wrap width (default: auto-detect terminal width)
opndossier convert config.xml --wrap 120

# Disable text wrapping
opndossier convert config.xml --no-wrap
```

### Comprehensive Reports

```bash
# Generate detailed comprehensive report
opndossier convert config.xml --comprehensive

# Include system tunables in output
opndossier convert config.xml --include-tunables
```

### Audit Mode

opnDossier includes built-in security auditing with compliance plugins:

```bash
# Blue team defensive audit with STIG and SANS compliance
opndossier convert config.xml --audit-mode blue --audit-plugins stig,sans

# Red team attack surface analysis
opndossier convert config.xml --audit-mode red

# Red team with blackhat commentary
opndossier convert config.xml --audit-mode red --audit-blackhat

# Standard documentation with all compliance checks
opndossier convert config.xml --audit-mode standard --audit-plugins stig,sans,firewall
```

Available audit modes:

| Mode       | Audience   | Focus                                  |
| ---------- | ---------- | -------------------------------------- |
| `standard` | Operations | Neutral, comprehensive documentation   |
| `blue`     | Blue Team  | Defensive audit with security findings |
| `red`      | Red Team   | Attack surface and pivot points        |

Available compliance plugins: `stig`, `sans`, `firewall`

## Display Command

Renders configuration as formatted markdown directly in your terminal with syntax highlighting.

```bash
# Display configuration
opndossier display config.xml

# Display with a specific theme
opndossier display --theme dark config.xml
opndossier display --theme light config.xml

# Display specific sections
opndossier display --section system,network config.xml

# Display with custom wrap width
opndossier display --wrap 100 config.xml

# Display without text wrapping
opndossier display --no-wrap config.xml
```

Available themes: `auto` (default), `dark`, `light`, `none`

## Validate Command

Checks configuration files for correctness without performing conversion.

```bash
# Validate a single file
opndossier validate config.xml

# Validate multiple files
opndossier validate config1.xml config2.xml config3.xml

# Validate with verbose output
opndossier --verbose validate config.xml

# Validate with JSON error output (for automation)
opndossier --json-output validate config.xml
```

Validation includes XML syntax checks, OPNsense schema validation, required field checks, and cross-field consistency checks.

### Recommended Workflow

Validate before converting:

```bash
opndossier validate config.xml && opndossier convert config.xml -o output.md
```

## Global Flags

These flags apply to all commands:

```bash
# Verbose output with debug logging
opndossier --verbose convert config.xml

# Quiet mode (errors only)
opndossier --quiet convert config.xml

# Use custom config file
opndossier --config ./custom-config.yaml convert config.xml

# Disable progress indicators
opndossier --no-progress convert config.xml

# Color control
opndossier --color never convert config.xml

# JSON error output (for automation)
opndossier --json-output validate config.xml
```

## Configuration Management

### Using Configuration Files

Create `~/.opnDossier.yaml` for persistent settings:

```yaml
# Default settings for all operations
verbose: false
quiet: false
format: markdown
wrap: 120
```

### Environment Variables

Use environment variables with the `OPNDOSSIER_` prefix:

```bash
# Set logging preferences
export OPNDOSSIER_VERBOSE=true

# Set default format
export OPNDOSSIER_FORMAT=json

# Run with environment configuration
opndossier convert config.xml
```

### Precedence

Configuration follows a clear precedence order (highest to lowest):

1. Command-line flags
2. Environment variables (`OPNDOSSIER_*`)
3. Configuration file (`~/.opnDossier.yaml`)
4. Default values

## Common Workflows

### 1. Document Network Configuration

```bash
# Basic documentation workflow
opndossier convert config.xml -o network-documentation.md

# With verbose logging for troubleshooting
opndossier --verbose convert config.xml -o network-docs.md

# Generate multiple formats
opndossier convert config.xml -f markdown -o config.md
opndossier convert config.xml -f json -o config.json
```

### 2. Security Audit

```bash
# Run a defensive audit
opndossier convert config.xml --audit-mode blue --audit-plugins stig,sans -o audit-report.md

# Run a red team assessment
opndossier convert config.xml --audit-mode red --audit-blackhat -o recon-report.md
```

### 3. Batch Processing

```bash
# Process multiple configuration files
opndossier convert *.xml

# Process files in a directory
find /path/to/configs -name "*.xml" -exec opndossier convert {} \;
```

### 4. Automated Documentation Pipeline

```bash
#!/bin/bash

# Process configuration
opndossier convert /path/to/config.xml -o ./docs/network-config.md

# Check if successful
if [ $? -eq 0 ]; then
    echo "Documentation generated successfully"
else
    echo "Documentation generation failed"
    exit 1
fi
```

### 5. CI/CD Integration

```yaml
# .github/workflows/docs.yml
name: Generate Documentation
on: [push]

jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Generate Documentation
        run: opndossier convert config.xml -o docs/network-config.md
```

## Error Handling

### XML Parsing Errors

```bash
opndossier convert invalid-config.xml
# Error: failed to parse XML from invalid-config.xml: XML syntax error on line 42
```

### File Permission Issues

```bash
opndossier convert /root/config.xml
# Error: failed to open file /root/config.xml: permission denied
```

### Conflicting Flags

```bash
opndossier --verbose --quiet convert config.xml
# Error: `verbose` and `quiet` are mutually exclusive

opndossier convert config.xml --wrap 100 --no-wrap
# Error: --no-wrap and --wrap flags are mutually exclusive
```

## Debugging Tips

1. **Use verbose mode** for detailed processing information:

   ```bash
   opndossier --verbose convert config.xml
   ```

2. **Validate first** to isolate parsing issues from conversion issues:

   ```bash
   opndossier validate config.xml
   ```

3. **Capture logs** for automated analysis:

   ```bash
   opndossier --verbose convert config.xml > output.md 2> debug.log
   ```

---

For more configuration options, see the [Configuration Reference](configuration-reference.md).
