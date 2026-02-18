# Basic Documentation Examples

This guide covers the most common use cases for generating documentation from OPNsense configuration files.

## Simple Configuration Conversion

### Convert to Markdown (Default)

```bash
# Basic conversion - outputs to console
opndossier convert config.xml

# Save to file
opndossier convert config.xml -o network-docs.md

# Convert with verbose output
opndossier --verbose convert config.xml -o network-docs.md
```

### Convert to JSON Format

```bash
# Convert to JSON for programmatic access
opndossier convert config.xml -f json -o config.json

# Pretty-printed JSON (pipe through jq)
opndossier convert config.xml -f json | jq '.'

# Extract specific sections from JSON output
opndossier convert config.xml -f json | jq '.system'
opndossier convert config.xml -f json | jq '.interfaces'
```

### Convert to YAML Format

```bash
# Convert to YAML for configuration management
opndossier convert config.xml -f yaml -o config.yaml

# Use in Ansible playbooks
opndossier convert config.xml -f yaml > vars/firewall_config.yml
```

### Convert to Other Formats

```bash
# Plain text (markdown without formatting)
opndossier convert config.xml -f text -o output.txt

# Self-contained HTML report
opndossier convert config.xml -f html -o report.html
```

Short aliases are also supported: `md`, `yml`, `txt`, `htm`.

## File Management Examples

### Multiple File Processing

```bash
# Convert multiple files at once (each gets an auto-named output file)
opndossier convert config1.xml config2.xml config3.xml

# Convert multiple files to the same format
opndossier convert -f json config1.xml config2.xml config3.xml
```

When processing multiple files, the `--output` flag is ignored and each output file is named based on its input file with the appropriate extension.

### Batch Processing with Shell

```bash
# Process all XML files in current directory
for file in *.xml; do
    opndossier convert "$file" -o "${file%.xml}.md"
done

# Process files in subdirectories
find . -name "*.xml" -exec opndossier convert {} \;

# Process with parallel execution
find . -name "*.xml" | xargs -P 4 -I {} opndossier convert {}
```

### Output File Organization

```bash
# Create organized directory structure
mkdir -p docs/{current,archive,backups}

# Generate current documentation
opndossier convert config.xml -o docs/current/network-config.md

# Archive with timestamp
opndossier convert config.xml -o "docs/archive/$(date +%Y-%m-%d)-config.md"

# Create backup documentation
opndossier convert backup-config.xml -o docs/backups/backup-config.md
```

## Configuration Management

### Using Configuration Files

Create `~/.opnDossier.yaml` for persistent settings:

```yaml
# Default settings
verbose: false
format: markdown
wrap: 120
```

### Environment Variables

```bash
# Set default output format
export OPNDOSSIER_FORMAT=json

# Set logging preferences
export OPNDOSSIER_VERBOSE=true

# Run with environment configuration
opndossier convert config.xml
```

### CLI Flag Overrides

```bash
# Override config file settings
opndossier convert config.xml -o custom.md --comprehensive

# Temporary verbose mode
opndossier --verbose convert config.xml

# Use custom config file
opndossier --config ./project-config.yaml convert config.xml
```

## Display Examples

### Terminal Display

```bash
# Display with syntax highlighting
opndossier display config.xml

# Display with specific theme
opndossier display --theme dark config.xml
opndossier display --theme light config.xml

# Display with no theme styling
opndossier display --theme none config.xml
```

### Section Filtering

```bash
# Display only system information
opndossier display --section system config.xml

# Display network and firewall sections
opndossier display --section network,firewall config.xml
```

## Validation Examples

### Basic Validation

```bash
# Validate single file
opndossier validate config.xml

# Validate with verbose output
opndossier --verbose validate config.xml

# Validate multiple files
opndossier validate config1.xml config2.xml config3.xml
```

### Validation in Workflows

```bash
# Validate before converting (recommended)
opndossier validate config.xml && opndossier convert config.xml

# Validate and convert in one step
opndossier validate config.xml && opndossier convert config.xml -o validated-config.md

# Check validation status
if opndossier validate config.xml; then
    echo "Configuration is valid"
    opndossier convert config.xml -o config.md
else
    echo "Configuration has errors"
    exit 1
fi
```

## Common Workflow Examples

### Daily Documentation Update

```bash
#!/bin/bash
# daily-docs.sh

# Create timestamp
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

# Validate and convert
if opndossier validate config.xml; then
    opndossier convert config.xml -o "docs/network-config-${TIMESTAMP}.md"
    echo "Documentation updated successfully"
else
    echo "Configuration validation failed"
    exit 1
fi
```

### Configuration Comparison

```bash
#!/bin/bash
# compare-configs.sh

# Convert both configurations to JSON
opndossier convert current-config.xml -f json -o current.json
opndossier convert previous-config.xml -f json -o previous.json

# Compare using jq (if available)
if command -v jq &> /dev/null; then
    jq -S . current.json > current-sorted.json
    jq -S . previous.json > previous-sorted.json
    diff current-sorted.json previous-sorted.json
else
    echo "Install jq for better comparison: brew install jq"
    diff current.json previous.json
fi
```

### Backup Documentation

```bash
#!/bin/bash
# backup-docs.sh

BACKUP_DIR="backups/$(date +%Y/%m)"
mkdir -p "$BACKUP_DIR"

# Create backup documentation in multiple formats
opndossier convert config.xml -o "${BACKUP_DIR}/config-$(date +%Y-%m-%d).md"
opndossier convert config.xml -f json -o "${BACKUP_DIR}/config-$(date +%Y-%m-%d).json"

echo "Backup documentation created in ${BACKUP_DIR}"
```

## Best Practices

### 1. Always Validate First

```bash
# Good practice
opndossier validate config.xml && opndossier convert config.xml

# Bad practice - may produce incomplete output on invalid input
opndossier convert config.xml
```

### 2. Use Descriptive Output Names

```bash
# Good
opndossier convert config.xml -o "network-config-$(date +%Y-%m-%d).md"

# Bad
opndossier convert config.xml -o output.md
```

### 3. Organize Output Files

```bash
# Create organized structure
mkdir -p docs/{current,archive,backups,exports}

# Use appropriate directories
opndossier convert config.xml -o docs/current/network.md
opndossier convert backup.xml -o docs/backups/backup.md
opndossier convert config.xml -f json -o docs/exports/config.json
```

### 4. Use Environment Variables for Automation

```bash
# Set up environment
export OPNDOSSIER_VERBOSE=true
export OPNDOSSIER_FORMAT=json

# Run commands with consistent settings
opndossier convert config.xml -o output.json
```

### 5. Handle Errors Gracefully

```bash
#!/bin/bash
# robust-conversion.sh

set -e  # Exit on any error

# Validate configuration
if ! opndossier validate config.xml; then
    echo "Configuration validation failed"
    exit 1
fi

# Convert with error handling
if opndossier convert config.xml -o network-docs.md; then
    echo "Documentation generated successfully"
else
    echo "Documentation generation failed"
    exit 1
fi
```

---

**Next Steps:**

- For automation, see [Automation and Scripting](automation-scripting.md)
- For advanced configuration, see [Advanced Configuration](advanced-configuration.md)
- For troubleshooting, see [Troubleshooting](troubleshooting.md)
