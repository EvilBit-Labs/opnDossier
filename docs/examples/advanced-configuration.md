# Advanced Configuration Examples

This guide covers advanced configuration options and customization techniques for opnDossier.

## Theme Customization

### Built-in Themes

```bash
# Use light theme
opnDossier display config.xml --theme light

# Use dark theme
opnDossier display config.xml --theme dark

# Auto-detect theme
opnDossier display config.xml --theme auto

# No theme (plain text)
opnDossier display config.xml --theme none
```

### Custom Theme Configuration

Create a custom theme configuration:

```yaml
# ~/.opnDossier/themes/custom.yaml
colors:
  primary: '#2563eb'
  secondary: '#64748b'
  success: '#059669'
  warning: '#d97706'
  error: '#dc2626'
  background: '#ffffff'
  foreground: '#1f2937'

styles:
  header:
    bold: true
    color: primary
  subheader:
    color: secondary
  success:
    color: success
  warning:
    color: warning
  error:
    color: error
```

### Using Custom Themes

```bash
# Use custom theme
opnDossier display config.xml --theme custom

# Create theme-specific output
opnDossier display config.xml --theme dark --wrap 120
```

## Section Filtering

### Basic Section Filtering

```bash
# Display only system information
opnDossier display config.xml --section system

# Display network and firewall sections
opnDossier display config.xml --section network,firewall

# Display multiple sections
opnDossier display config.xml --section system,interfaces,firewall
```

### Advanced Section Filtering

```bash
# Filter by specific interface
opnDossier display config.xml --section interfaces.wan,interfaces.lan

# Filter by rule type
opnDossier display config.xml --section firewall.rules.pass,firewall.rules.block

# Filter by service
opnDossier display config.xml --section services.dhcp,services.dns
```

## Output Formatting

### Text Wrapping

```bash
# Set text wrap width
opnDossier display config.xml --wrap 80

# No text wrapping
opnDossier display config.xml --wrap 0

# Wide format for large screens
opnDossier display config.xml --wrap 160
```

### Custom Output Formats

#### JSON with Custom Structure

```bash
# Convert to JSON with specific structure
opnDossier convert config.xml -f json | jq '{
  hostname: .system.hostname,
  domain: .system.domain,
  interfaces: .interfaces,
  rule_count: (.filter.rules | length)
}'
```

#### YAML with Filtering

```bash
# Convert to YAML with specific sections
opnDossier convert config.xml -f yaml | yq '.system, .interfaces'
```

## Advanced Configuration Files

### Comprehensive Configuration

Create `~/.opnDossier.yaml`:

```yaml
# Global configuration
verbose: false
theme: auto

# Output settings
output_file: ./network-docs.md
wrap_width: 120

# Display settings
sections: [system, interfaces, firewall, nat]
exclude_sections: [certificates, vpn]

# Performance settings
max_memory: 512MB
timeout: 300s
```

### Environment-Specific Configuration

Create `~/.opnDossier/production.yaml`:

```yaml
# Production environment settings
output_file: /var/www/docs/network-config.md

# Performance settings
max_memory: 1GB
timeout: 600s
```

Create `~/.opnDossier/development.yaml`:

```yaml
# Development environment settings
verbose: true
output_file: ./dev-docs.md

# Performance settings
max_memory: 256MB
timeout: 60s
```

### Using Environment-Specific Configs

```bash
# Use production configuration
opnDossier --config ~/.opnDossier/production.yaml convert config.xml

# Use development configuration
opnDossier --config ~/.opnDossier/development.yaml convert config.xml

# Override specific settings
opnDossier --config ~/.opnDossier/production.yaml --verbose convert config.xml
```

## Advanced Workflows

### Multi-Format Generation

```bash
#!/bin/bash
# multi-format-generator.sh

CONFIG_FILE="$1"
OUTPUT_DIR="$2"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate multiple formats
opnDossier convert "$CONFIG_FILE" -o "$OUTPUT_DIR/network-config.md"
opnDossier convert "$CONFIG_FILE" -f json -o "$OUTPUT_DIR/network-config.json"
opnDossier convert "$CONFIG_FILE" -f yaml -o "$OUTPUT_DIR/network-config.yaml"

echo "Multi-format generation completed in $OUTPUT_DIR"
```

### Conditional Processing

```bash
#!/bin/bash
# conditional-processing.sh

CONFIG_FILE="$1"

# Check file size
FILE_SIZE=$(stat -c%s "$CONFIG_FILE")

if [ "$FILE_SIZE" -gt 1048576 ]; then
    # Large file - use optimized settings
    opnDossier convert "$CONFIG_FILE" \
        --max-memory 1GB \
        --timeout 600s \
        -o large-config-report.md
else
    # Small file - use standard settings
    opnDossier convert "$CONFIG_FILE" \
      --comprehensive \
      -o standard-report.md
fi
```

## Performance Optimization

### Memory Management

```bash
# Set memory limits
opnDossier convert config.xml --max-memory 512MB

# Monitor memory usage
/usr/bin/time -v opnDossier convert config.xml

# Use streaming for large files
opnDossier convert large-config.xml --streaming
```

### Parallel Processing

```bash
# Process multiple files in parallel
find configs/ -name "*.xml" | xargs -P 4 -I {} \
    opnDossier convert {} -o docs/{}.md

# Batch processing with parallel execution
for config in configs/*.xml; do
    opnDossier convert "$config" -o "docs/$(basename "$config" .xml).md" &
done
wait
```

## Best Practices

### 1. Configuration Management

```bash
# Use version control for configurations
git init ~/.opnDossier
cd ~/.opnDossier
git add .
git commit -m "Initial opnDossier configuration"

# Use environment-specific configs
export OPNDOSSIER_CONFIG=~/.opnDossier/production.yaml
```

### 2. Performance Monitoring

```bash
# Track memory usage
opnDossier convert config.xml --memory-profile

# Optimize based on usage patterns
opnDossier convert config.xml --optimize --cache-results
```

---

**Next Steps:**

- For basic documentation, see [Basic Documentation](basic-documentation.md)
- For audit and compliance, see [Audit and Compliance](audit-compliance.md)
- For automation, see [Automation and Scripting](automation-scripting.md)
