# opnDossier Examples

## Overview

This document provides real-world usage examples and patterns for opnDossier.

## Basic Usage Examples

### Simple Configuration Report

```bash
# Generate a configuration report
opndossier convert config.xml -o report.md

# Generate comprehensive report with tunables
opndossier convert config.xml -o detailed-report.md --comprehensive --include-tunables
```

### Multi-Format Export

```bash
# Export in all supported formats
opndossier convert config.xml -o report.md
opndossier convert config.xml -f json -o config-data.json
opndossier convert config.xml -f yaml -o config-data.yaml
opndossier convert config.xml -f text -o report.txt
opndossier convert config.xml -f html -o report.html
```

## CI/CD Pipeline Integration

### GitHub Actions Documentation Pipeline

```yaml
# .github/workflows/documentation.yml
name: Generate Network Documentation

on:
  push:
    paths:
      - configs/*.xml

jobs:
  generate-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Validate Configurations
        run: opndossier validate configs/*.xml

      - name: Generate Reports
        run: |
          mkdir -p reports
          for config in configs/*.xml; do
            filename=$(basename "$config" .xml)
            opndossier convert "$config" \
              --comprehensive \
              -o "reports/${filename}.md"
          done

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: network-reports
          path: reports/
```

## Batch Processing Script

```bash
#!/bin/bash
# batch-process.sh - Process multiple OPNsense configurations

set -euo pipefail

CONFIG_DIR="${1:?Usage: $0 <config-dir> [output-dir]}"
OUTPUT_DIR="${2:-./reports}"

mkdir -p "$OUTPUT_DIR"

echo "Starting batch processing..."

for config_file in "$CONFIG_DIR"/*.xml; do
    if [[ -f "$config_file" ]]; then
        filename=$(basename "$config_file" .xml)
        output_file="$OUTPUT_DIR/${filename}.md"

        echo "Processing: $config_file"

        if opndossier validate "$config_file" > /dev/null 2>&1; then
            opndossier convert "$config_file" \
                --comprehensive \
                -o "$output_file"
            echo "  Generated: $output_file"
        else
            echo "  Failed to validate: $config_file"
        fi
    fi
done

echo "Batch processing complete. Reports saved to: $OUTPUT_DIR"
```

## JSON Processing Examples

### Extract Firewall Rules

```bash
# Convert to JSON and extract firewall rules
opndossier convert config.xml -f json | jq '.firewallRules[]'

# Count rules by type
opndossier convert config.xml -f json | jq '.firewallRules | group_by(.type) | map({type: .[0].type, count: length})'

# Find rules allowing all traffic
opndossier convert config.xml -f json | jq '.firewallRules[] | select(.source.address == "any" and .destination.address == "any")'
```

### Extract System Information

```bash
# Get system summary
opndossier convert config.xml -f json | jq '{
  hostname: .system.hostname,
  domain: .system.domain,
  timezone: .system.timezone
}'

# Get interface summary
opndossier convert config.xml -f json | jq '.interfaces[] | {name, ipAddress, subnet}'
```

## Configuration Comparison

Use the built-in `diff` command for content-aware, security-scored configuration comparison:

```bash
# Compare two configs with terminal output
opndossier diff old-config.xml new-config.xml

# Generate markdown diff report
opndossier diff old-config.xml new-config.xml -f markdown -o changes.md

# Compare only firewall rules
opndossier diff old-config.xml new-config.xml --section firewall

# Show only security-relevant changes
opndossier diff old-config.xml new-config.xml --security

# Generate JSON diff for automation
opndossier diff old-config.xml new-config.xml -f json | jq '.changes[]'
```

## Performance Tips

### Process Specific Sections

For large configurations, filter to specific sections for faster processing:

```bash
# Process only firewall and network sections
opndossier convert large-config.xml --section firewall,network -o partial-report.md
```

### Parallel Multi-File Processing

```bash
# Process multiple files in parallel (4 workers)
find configs/ -name "*.xml" | xargs -P 4 -I {} \
    sh -c 'opndossier convert "$1" -o "docs/$(basename "$1" .xml).md"' _ {}
```

## Best Practices Summary

1. **Always validate first** - Run `opndossier validate` before converting
2. **Use JSON for analysis** - Export to JSON and use `jq` for programmatic processing
3. **Automate with CI/CD** - Integrate into pipelines for automated documentation
4. **Version control outputs** - Keep generated reports in version control for change tracking

For more detailed examples, see:

- [Basic Documentation](examples/basic-documentation.md)
- [Automation and Scripting](examples/automation-scripting.md)
- [Advanced Configuration](examples/advanced-configuration.md)
- [Troubleshooting](examples/troubleshooting.md)
