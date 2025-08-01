# Basic Documentation Examples

This guide covers the most common use cases for generating documentation from OPNsense configuration files.

## Simple Configuration Conversion

### Convert to Markdown (Default)

```bash
# Basic conversion - outputs to console
opnFocus convert config.xml

# Save to file
opnFocus convert config.xml -o network-docs.md

# Convert with verbose output
opnFocus --verbose convert config.xml -o network-docs.md
```

**Example Output:**

```markdown
# OPNsense Configuration Documentation

## System Information
- **Hostname**: firewall.example.com
- **Domain**: example.com
- **Theme**: opnsense

## Interfaces
| Name | IP Address | Subnet | Description |
|------|------------|--------|-------------|
| WAN | 192.168.1.1 | /24 | Internet connection |
| LAN | 10.0.0.1 | /24 | Internal network |

## Firewall Rules
...
```

### Convert to JSON Format

```bash
# Convert to JSON for programmatic access
opnFocus convert config.xml -f json -o config.json

# Pretty-printed JSON
opnFocus convert config.xml -f json | jq '.'

# Extract specific sections
opnFocus convert config.xml -f json | jq '.system'
opnFocus convert config.xml -f json | jq '.interfaces'
```

**Example Output:**

```json
{
  "system": {
    "hostname": "firewall.example.com",
    "domain": "example.com",
    "theme": "opnsense"
  },
  "interfaces": {
    "wan": {
      "ipaddr": "192.168.1.1",
      "subnet": "24",
      "descr": "Internet connection"
    },
    "lan": {
      "ipaddr": "10.0.0.1",
      "subnet": "24",
      "descr": "Internal network"
    }
  }
}
```

### Convert to YAML Format

```bash
# Convert to YAML for configuration management
opnFocus convert config.xml -f yaml -o config.yaml

# Use in Ansible playbooks
opnFocus convert config.xml -f yaml > vars/firewall_config.yml
```

**Example Output:**

```yaml
system:
  hostname: firewall.example.com
  domain: example.com
  theme: opnsense

interfaces:
  wan:
    ipaddr: 192.168.1.1
    subnet: 24
    descr: Internet connection
  lan:
    ipaddr: 10.0.0.1
    subnet: 24
    descr: Internal network
```

## File Management Examples

### Multiple File Processing

```bash
# Convert multiple files at once
opnFocus convert config1.xml config2.xml config3.xml

# Each file gets appropriate extension
# config1.xml -> config1.md
# config2.xml -> config2.json
# config3.xml -> config3.yaml

# Convert multiple files to same format
opnFocus convert -f json config1.xml config2.xml config3.xml
```

### Batch Processing with Shell

```bash
# Process all XML files in current directory
for file in *.xml; do
    opnFocus convert "$file" -o "${file%.xml}.md"
done

# Process files in subdirectories
find . -name "*.xml" -exec opnFocus convert {} -o {}.md \;

# Process with parallel execution
find . -name "*.xml" | xargs -P 4 -I {} opnFocus convert {} -o {}.md
```

### Output File Organization

```bash
# Create organized directory structure
mkdir -p docs/{current,archive,backups}

# Generate current documentation
opnFocus convert config.xml -o docs/current/network-config.md

# Archive with timestamp
opnFocus convert config.xml -o docs/archive/$(date +%Y-%m-%d)-config.md

# Create backup documentation
opnFocus convert backup-config.xml -o docs/backups/backup-config.md
```

## Configuration Management

### Using Configuration Files

Create `~/.opnFocus.yaml` for persistent settings:

```yaml
# Default settings
log_level: info
log_format: text
output_file: ./network-docs.md
verbose: false
theme: auto
```

### Environment Variables

```bash
# Set default output location
export OPNFOCUS_OUTPUT_FILE="./documentation.md"

# Set logging preferences
export OPNFOCUS_LOG_LEVEL=debug
export OPNFOCUS_LOG_FORMAT=json

# Run with environment configuration
opnFocus convert config.xml
```

### CLI Flag Overrides

```bash
# Override config file settings
opnFocus --log_level=debug --output=custom.md convert config.xml

# Temporary verbose mode
opnFocus --verbose convert config.xml

# Use custom config file
opnFocus --config ./project-config.yaml convert config.xml
```

## Display Examples

### Terminal Display

```bash
# Display with syntax highlighting
opnFocus display config.xml

# Display with specific theme
opnFocus display --theme dark config.xml
opnFocus display --theme light config.xml

# Display without validation
opnFocus display --no-validate config.xml
```

### Section Filtering

```bash
# Display only system information
opnFocus display --section system config.xml

# Display network and firewall sections
opnFocus display --section network,firewall config.xml

# Display with custom template
opnFocus display --template detailed config.xml
```

## Validation Examples

### Basic Validation

```bash
# Validate single file
opnFocus validate config.xml

# Validate with verbose output
opnFocus --verbose validate config.xml

# Validate multiple files
opnFocus validate config1.xml config2.xml config3.xml
```

### Validation in Workflows

```bash
# Validate before converting (recommended)
opnFocus validate config.xml && opnFocus convert config.xml

# Validate and convert in one step
opnFocus validate config.xml && opnFocus convert config.xml -o validated-config.md

# Check validation status
if opnFocus validate config.xml; then
    echo "Configuration is valid"
    opnFocus convert config.xml -o config.md
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

# Set up environment
export OPNFOCUS_LOG_FORMAT=json
export OPNFOCUS_LOG_LEVEL=info

# Create timestamp
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

# Validate and convert
if opnFocus validate config.xml; then
    opnFocus convert config.xml -o "docs/network-config-${TIMESTAMP}.md"
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
opnFocus convert current-config.xml -f json -o current.json
opnFocus convert previous-config.xml -f json -o previous.json

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

# Create backup documentation
opnFocus convert config.xml -o "${BACKUP_DIR}/config-$(date +%Y-%m-%d).md"

# Create JSON backup for programmatic access
opnFocus convert config.xml -f json -o "${BACKUP_DIR}/config-$(date +%Y-%m-%d).json"

echo "Backup documentation created in ${BACKUP_DIR}"
```

## Best Practices

### 1. Always Validate First

```bash
# Good practice
opnFocus validate config.xml && opnFocus convert config.xml

# Bad practice
opnFocus convert config.xml  # May fail silently
```

### 2. Use Descriptive Output Names

```bash
# Good
opnFocus convert config.xml -o "network-config-$(date +%Y-%m-%d).md"

# Bad
opnFocus convert config.xml -o output.md
```

### 3. Organize Output Files

```bash
# Create organized structure
mkdir -p docs/{current,archive,backups,exports}

# Use appropriate directories
opnFocus convert config.xml -o docs/current/network.md
opnFocus convert backup.xml -o docs/backups/backup.md
opnFocus convert config.xml -f json -o docs/exports/config.json
```

### 4. Use Environment Variables for Automation

```bash
# Set up environment
export OPNFOCUS_LOG_FORMAT=json
export OPNFOCUS_LOG_LEVEL=info
export OPNFOCUS_OUTPUT_FILE="./docs/network-config.md"

# Run commands
opnFocus validate config.xml
opnFocus convert config.xml
```

### 5. Handle Errors Gracefully

```bash
#!/bin/bash
# robust-conversion.sh

set -e  # Exit on any error

# Validate configuration
if ! opnFocus validate config.xml; then
    echo "Configuration validation failed"
    exit 1
fi

# Convert with error handling
if opnFocus convert config.xml -o network-docs.md; then
    echo "Documentation generated successfully"
else
    echo "Documentation generation failed"
    exit 1
fi
```

---

**Next Steps:**

- For security auditing, see [Audit and Compliance](audit-compliance.md)
- For automation, see [Automation and Scripting](automation-scripting.md)
- For troubleshooting, see [Troubleshooting](troubleshooting.md)
