# Advanced Configuration Examples

This guide covers advanced configuration options and customization techniques for opnDossier.

## Theme Customization

### Built-in Themes

opnDossier supports four display themes for terminal rendering:

```bash
# Auto-detect theme based on terminal
opndossier display config.xml --theme auto

# Use light theme
opndossier display config.xml --theme light

# Use dark theme
opndossier display config.xml --theme dark

# No theme (plain text output)
opndossier display config.xml --theme none
```

Available themes: `auto` (default), `dark`, `light`, `none`.

## Section Filtering

### Basic Section Filtering

```bash
# Display only system information
opndossier display config.xml --section system

# Display network and firewall sections
opndossier display config.xml --section network,firewall

# Display multiple sections
opndossier display config.xml --section system,network,firewall

# Convert only specific sections
opndossier convert config.xml --section system,network -o partial-report.md
```

## Output Formatting

### Text Wrapping

```bash
# Set text wrap width (range: 40-200 columns)
opndossier display config.xml --wrap 80

# Wide format for large screens
opndossier display config.xml --wrap 160

# Disable text wrapping entirely
opndossier display config.xml --no-wrap

# Auto-detect terminal width (default behavior)
opndossier display config.xml --wrap -1
```

The `--wrap` and `--no-wrap` flags are mutually exclusive.

### Comprehensive Reports

```bash
# Generate detailed comprehensive report
opndossier convert config.xml --comprehensive -o detailed-report.md

# Include system tunables in the report
opndossier convert config.xml --include-tunables -o tunables-report.md

# Combine comprehensive with tunables
opndossier convert config.xml --comprehensive --include-tunables -o full-report.md
```

### Custom Output Formats

#### JSON with Custom Processing

```bash
# Convert to JSON and extract specific data with jq
opndossier convert config.xml -f json | jq '{
  hostname: .system.hostname,
  domain: .system.domain,
  interfaces: .interfaces
}'
```

#### YAML with Filtering

```bash
# Convert to YAML and extract sections with yq
opndossier convert config.xml -f yaml | yq '.system'
```

## Configuration File

### Basic Configuration

Create `~/.opnDossier.yaml` for persistent settings:

```yaml
# Logging configuration
verbose: false
quiet: false

# Output settings
format: markdown
wrap: 120

# Content options
sections: []
```

### Using a Custom Config File

```bash
# Use a project-specific config
opndossier --config ./project-config.yaml convert config.xml

# Override specific settings from the config file
opndossier --config ./project-config.yaml --verbose convert config.xml
```

### Configuration Precedence

Settings are applied in this order (highest to lowest priority):

1. **Command-line flags** - Direct CLI arguments
2. **Environment variables** - `OPNDOSSIER_*` prefixed variables
3. **Configuration file** - `~/.opnDossier.yaml`
4. **Default values** - Built-in defaults

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
opndossier convert "$CONFIG_FILE" -o "$OUTPUT_DIR/network-config.md"
opndossier convert "$CONFIG_FILE" -f json -o "$OUTPUT_DIR/network-config.json"
opndossier convert "$CONFIG_FILE" -f yaml -o "$OUTPUT_DIR/network-config.yaml"
opndossier convert "$CONFIG_FILE" -f html -o "$OUTPUT_DIR/network-config.html"

echo "Multi-format generation completed in $OUTPUT_DIR"
```

### Conditional Processing

```bash
#!/bin/bash
# conditional-processing.sh

CONFIG_FILE="$1"

# Validate before any processing
if ! opndossier validate "$CONFIG_FILE"; then
    echo "Configuration validation failed"
    exit 1
fi

# Generate standard report
opndossier convert "$CONFIG_FILE" \
    --comprehensive \
    -o standard-report.md

# Generate JSON export for programmatic processing
opndossier convert "$CONFIG_FILE" \
    -f json \
    -o config-data.json

echo "Processing complete"
```

### Parallel Processing

```bash
# Process multiple files in parallel
find configs/ -name "*.xml" | xargs -P 4 -I {} \
    opndossier convert {} -o docs/{}.md

# Batch processing with parallel execution
for config in configs/*.xml; do
    opndossier convert "$config" -o "docs/$(basename "$config" .xml).md" &
done
wait
```

## Environment Variables

All configuration options can be set via environment variables:

```bash
# Logging preferences
export OPNDOSSIER_VERBOSE=true
export OPNDOSSIER_QUIET=false

# Output settings
export OPNDOSSIER_FORMAT=json
export OPNDOSSIER_WRAP=100

# Use in scripts
opndossier convert config.xml -o output.json
```

## Best Practices

### 1. Use Configuration Files for Persistent Settings

```bash
# Store frequently used settings in ~/.opnDossier.yaml
cat > ~/.opnDossier.yaml << 'EOF'
verbose: false
format: markdown
wrap: 120
EOF
```

### 2. Use Environment Variables for CI/CD

```bash
#!/bin/bash
# ci-pipeline.sh

export OPNDOSSIER_QUIET=true
export OPNDOSSIER_FORMAT=json

opndossier convert config.xml -o report.json
```

### 3. Use CLI Flags for One-off Overrides

```bash
# Debug a specific run
opndossier --verbose convert problematic-config.xml

# Generate output in a different format temporarily
opndossier convert config.xml -f yaml -o temp-output.yaml
```

---

**Next Steps:**

- For basic documentation, see [Basic Documentation](basic-documentation.md)
- For automation, see [Automation and Scripting](automation-scripting.md)
- For troubleshooting, see [Troubleshooting](troubleshooting.md)
