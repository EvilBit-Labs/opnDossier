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
opndossier convert config.xml -f json | jq '.filter.rule[]'

# Count rules by type
opndossier convert config.xml -f json | jq '.filter.rule | group_by(.type) | map({type: .[0].type, count: length})'

# Find rules allowing all traffic
opndossier convert config.xml -f json | jq '.filter.rule[] | select(.source.any != null and .destination.any != null)'
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
opndossier convert config.xml -f json | jq '.interfaces'
```

## Configuration Comparison

```bash
#!/bin/bash
# compare-configs.sh - Compare two OPNsense configurations

CONFIG_OLD="$1"
CONFIG_NEW="$2"

# Convert both to sorted JSON
opndossier convert "$CONFIG_OLD" -f json | jq -S . > /tmp/old-config.json
opndossier convert "$CONFIG_NEW" -f json | jq -S . > /tmp/new-config.json

# Compare
diff /tmp/old-config.json /tmp/new-config.json

# Clean up
rm -f /tmp/old-config.json /tmp/new-config.json
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
